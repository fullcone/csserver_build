#!/usr/bin/env python3
"""
Upload file to ModelScope with retry and verification.
"""

import os
import sys
import time

def main():
    from modelscope.hub.api import HubApi
    
    token = os.environ.get('MODELSCOPE_TOKEN')
    if not token:
        print("Error: MODELSCOPE_TOKEN not set")
        sys.exit(1)
    
    api = HubApi()
    api.login(token)
    
    REPO_ID = 'q9113979/yuyinceshi'
    LOCAL_FILE = 'csserver-all-in-one.7z'
    REMOTE_FILE = 'voice.7z'
    MAX_RETRIES = 3
    MIN_FILE_SIZE = 300 * 1024 * 1024  # 300MB
    
    if not os.path.exists(LOCAL_FILE):
        print(f"Error: Local file not found: {LOCAL_FILE}")
        sys.exit(1)
    
    local_size = os.path.getsize(LOCAL_FILE)
    print(f"Local file size: {local_size} bytes ({local_size / 1024 / 1024:.2f} MB)")
    
    def verify_upload_via_api(max_retries=5, retry_delay=10):
        """Verify upload using ModelScope SDK API with retry mechanism."""
        for retry in range(1, max_retries + 1):
            try:
                files = api.get_model_files(REPO_ID, revision='master')
                for f in files:
                    # Handle both dict and object responses
                    if isinstance(f, dict):
                        name = f.get('Name') or f.get('name') or f.get('Path') or f.get('path', '')
                        size = f.get('Size') or f.get('size', 0)
                    else:
                        name = getattr(f, 'Name', None) or getattr(f, 'name', None) or getattr(f, 'Path', None) or getattr(f, 'path', '')
                        size = getattr(f, 'Size', None) or getattr(f, 'size', 0)
                    
                    if name == REMOTE_FILE or name.endswith('/' + REMOTE_FILE):
                        file_size = int(size) if size else 0
                        print(f"Found: {name}, size: {file_size} bytes ({file_size / 1024 / 1024:.2f} MB)")
                        if file_size >= MIN_FILE_SIZE:
                            return file_size
                        print(f"Size too small, retry {retry}/{max_retries}...")
                        break
                else:
                    print(f"File not found, retry {retry}/{max_retries}...")
                
                if retry < max_retries:
                    time.sleep(retry_delay)
            except Exception as e:
                print(f"API error: {e}, retry {retry}/{max_retries}...")
                if retry < max_retries:
                    time.sleep(retry_delay)
        return 0
    
    # Upload with retry
    for attempt in range(1, MAX_RETRIES + 1):
        print(f"Upload attempt {attempt}/{MAX_RETRIES}...")
        try:
            api.upload_file(
                path_or_fileobj=LOCAL_FILE,
                path_in_repo=REMOTE_FILE,
                repo_id=REPO_ID,
                commit_message='CS Server Build'
            )
        except Exception as e:
            print(f"Upload exception: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(5)
            continue
        
        print("Waiting for server to process...")
        time.sleep(15)
        
        print("Verifying upload...")
        remote_size = verify_upload_via_api()
        if remote_size >= MIN_FILE_SIZE:
            print("Upload verified successfully!")
            break
        
        print(f"Verification failed, retry {attempt}/{MAX_RETRIES}...")
    else:
        print("WARNING: Upload verification failed after all retries")
    
    print(f"Download URL: https://www.modelscope.cn/models/{REPO_ID}/resolve/master/{REMOTE_FILE}")

if __name__ == '__main__':
    main()
