import boto3
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from threading import Lock

def ls(bucket_name, prefix='*'):
    s3 = boto3.resource('s3')
    bucket = s3.Bucket(bucket_name)
    all_files = bucket.objects.all()
    if prefix == "*":
        return all_files

    output = []
    for file in all_files:
        if file.startswith(prefix):
          output.append(file)
    return output

def get_path_data(path):
    if '/' in path:
        return path.split('/', 1)
    return path, '*'

#not working
def sync(src, dst):
    src_bucket, src_prefix = get_path_data(src)
    if src_prefix is None:
        src_prefix = '*'

    s3 = boto3.client('s3', use_ssl=False)
    files_to_download = [file.key for file in ls(src_bucket, src_prefix)] #takes forever for some reason :( we can override it with subprocess.run "aws s3 ls --recursive"
    files_to_download = list(set(files_to_download)) #this is the most important part, to maximize the download speed due to s3's rate limiting (more in my documentation)
    for file_to_download in files_to_download:
        file_name = file_to_download.key
        s3.download_file(src_bucket, file_name, '/'.join([dst, file_name]))

sqs = boto3.client('sqs')
def send_queue_message(body, queue_url):
    sqs.send_message(QueueUrl=queue_url, MessageBody=body)

def get_count_of_messages_in_queue(queue_url):
    return int(sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['ApproximateNumberOfMessages'])['Attributes']['ApproximateNumberOfMessages'])

all_messages_in_queue_lock = Lock()
all_messages_in_queue = []
def get_message(doesnt_matter, queue_url, should_delete_messages_in_queue):
    response = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10)
    if 'Messages' not in response:
        return  # empty queue or no more messages. Return to prevent infinite while True

    for message in response['Messages']:
        if should_delete_messages_in_queue:
            id = message['ReceiptHandle']
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=id)

        all_messages_in_queue_lock.acquire()
        all_messages_in_queue.append(message['Body'])
        all_messages_in_queue_lock.release()

# I was afraid of race conditions, however I put a 5m visibility timeout so there's 5m between sqs.receive_message and sqs.delete_message which is a ton of time
# MaxNumberOfMessages - "fewer messages might be returned" but that's ok,  it's better to process less than more (more can exceed a server's resources and the scrpit might stop due to OOM, this )
def receive_queue_messages(queue_url, max_number_of_messages, should_delete_messages_in_queue=True):
    with ThreadPoolExecutor(max_workers=10) as executor:
        task_list = range(max(1, round(max_number_of_messages/10)))
        executor.map(partial(get_message, queue_url=queue_url, should_delete_messages_in_queue=should_delete_messages_in_queue), task_list)
    return all_messages_in_queue

s3_client = boto3.client('s3')
def read_s3_text_file(bucket_name, file_name):
    data = s3_client.get_object(Bucket=bucket_name, Key=file_name)
    return data['Body'].read().decode("utf-8")