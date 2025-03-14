#! /usr/bin/env python

import json
import requests
from random import choices
import string
from copy import deepcopy
from pathlib import Path
from time import time
import argparse
import traceback
import tempfile
from shutil import move, rmtree
from zipfile import ZipFile
from sshkey_tools.keys import Ed25519PrivateKey


__all__ = [
  'list_ghssh_keys',
  'create_ghssh_key',
  'delete_ghssh_key',
]

API_URL = 'https://api.github.com'
http:requests.Session = None
BASE_HEADERS = {
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
}
DEFAULT_PASSWORD_TABLE:str = string.ascii_lowercase+string.digits
DEFAULT_CONFIG:dict = {
  'fine-grained-token':'your github fine-grained token',
}
VERBOSE:bool = False


# other functions

def vprint(*args, **kwargs) -> None:
  if VERBOSE:
    print(*args, **kwargs)

def get_rand_password(length:int, table:str=DEFAULT_PASSWORD_TABLE) -> str:
  return ''.join(choices(table, k=length))

def generate_ssh_key(password:str=None) -> tuple[str]:
  # Generate ED25519 keys (fixed key size)
  ed25519_key = Ed25519PrivateKey.generate()
  if password is not None and len(password) > 0:
    return (ed25519_key.to_string(password), ed25519_key.public_key.to_string())
  else:
    return (ed25519_key.to_string(), ed25519_key.public_key.to_string())

def status_not_good(status_code:int) -> bool:
  return (status_code < 200 or status_code >= 300)


# github ssh key features

def list_ghssh_keys() -> tuple[int,dict]:
  global sess
  resp = sess.get(API_URL+'/user/keys', headers=BASE_HEADERS)
  vprint(f'list_ghssh_keys(): {resp.json() = }')
  return resp.status_code,resp.json()

def create_ghssh_key(key_location:str, use_random_password:bool=True, random_table:str=DEFAULT_PASSWORD_TABLE) -> tuple[int,dict]:
  password = get_rand_password(length=5, table=random_table) if use_random_password else None
  priv,pub = generate_ssh_key(password=password)
  title = 'tmp-gh-ssh-key-' + str(int(time() * 1000))
  
  root = Path(key_location)
  priv_path = root/f'{title}'
  pub_path = root/f'{title}.pub'
  vprint(f'create_ghssh_key(): {password = }')
  vprint(f'create_ghssh_key(): {priv = }')
  vprint(f'create_ghssh_key(): {pub = }')
  with open(priv_path, 'w') as fp_priv, open(pub_path, 'w') as fp_pub:
    fp_priv.write(priv)
    fp_pub.write(pub)
  
  global sess
  headers = deepcopy(BASE_HEADERS)
  data = {
    'title':title,
    'key':pub
  }
  resp = sess.post(API_URL+'/user/keys', headers=headers, json=data)
  vprint(f'create_ghssh_key(): {resp.json() = }')
  return resp.status_code,{**resp.json(), 'key_password':password, 'priv_key_path':str(priv_path.resolve()), 'pub_key_path':str(pub_path.resolve())}

def delete_ghssh_key(key_id:int) -> bool:
  headers = deepcopy(BASE_HEADERS)
  resp = sess.delete(API_URL+f'/user/keys/{key_id}', headers=headers)
  vprint(f'delete_ghssh_key(): {resp.content = }')
  return (resp.status_code == 204)


# cli helper functions

def cli_generate_default_config(config_path:Path):
  print('Cannot find a ".config" file in script directory, generating a new one...')
  with open(config_path, 'w') as file:
    json.dump(DEFAULT_CONFIG, file, ensure_ascii=False, indent=2)
  print(f'Please fill-in all the information in thie newly generated configuration file:\n{str(config_path.resolve())}')

def cli_list_gh_keys(config):
  print('Listing ssh keys in your github account...')
  status,resp = list_ghssh_keys()
  if status_not_good(status):
    raise RuntimeError(f'Fail to list github ssh keys.')
  for r in resp:
    print(f'id={r["id"]}, title={r["title"]}')

def cli_create_new_gh_key(config, out_path, save_password=False, save_zip=False):
  out_path = Path(out_path)
  if not out_path.exists() or not out_path.is_dir():
    raise ValueError(f'Input out_path doesn\'t exists or isn\'t a directory: {str(out_path)}')
  tmp_path = Path(tempfile.mkdtemp())
  vprint(f'cli_create_new_gh_key(): {tmp_path = }')
  print('Create a new ssh key and upload to your github account...')
  status,resp = create_ghssh_key(tmp_path)
  if status_not_good(status):
    raise RuntimeError(f'Fail to create a new ssh key and upload to github.')
  print(f'Key Id: {resp["id"]}')
  print(f'Private Key: {out_path/Path(resp["priv_key_path"]).name}')
  print(f'Public Key: {out_path/Path(resp["pub_key_path"]).name}')
  print(f'The password for your key is: {resp["key_password"]}')
  if save_password:
    with open(tmp_path/'password.txt', 'w') as file:
      file.write(resp['key_password'])
    print(f'The password have been saved to file')
  if save_zip:
    with ZipFile(tmp_path/'keys.zip', 'w') as zp:
      for file in tmp_path.iterdir():
        if 'keys.zip' not in file.name:
          zp.write(file, f'keys/{file.name}')
    for file in tmp_path.iterdir():
      if 'keys.zip' not in file.name:
        file.unlink()
  for file in tmp_path.iterdir():
    move(file, out_path)
  if save_zip:
    rmtree(tmp_path, True)

def cli_remove_gh_key(config, key_id):
  print(f'Remove ssh key [{key_id}] from your github account...')
  resp = delete_ghssh_key(key_id)
  print(f'Result: {resp}')
  if not resp:
    raise ValueError(f'Fail to remove ssh key from github.')



def main():
  # arg parse
  parser = argparse.ArgumentParser()
  parser.add_argument(
    '-g','--generate-config',
    action='store_true', default=False,
    help='Generate a configuration file'
  )
  parser.add_argument(
    '-l','--list',
    action='store_true', default=False,
    help='List ssh keys in your github account'
  )
  parser.add_argument(
    '-c','--create',
    action='store_true', default=False,
    help='Create a new ssh key and upload to your github account'
  )
  parser.add_argument(
    '-r','--remove',
    action='store', default=-1, type=int, metavar='KEY_ID',
    help='Remove a ssh key specified by input id from your github account'
  )
  parser.add_argument(
    '-o','--output',
    action='store', default=None, metavar='KEY_FOLDER', type=str,
    help='Set output key folder'
  )
  parser.add_argument(
    '-P','--password',
    action='store_true', default=False,
    help='Also save password to file'
  )
  parser.add_argument(
    '-z','--zip',
    action='store_true', default=False,
    help='Create a zip archive contains ssh keys & password file. You can use -o to set archive output folder'
  )
  parser.add_argument(
    '-v','--verbose',
    action='store_true', default=False,
    help='Toggle verbose mode'
  )
  
  args = parser.parse_args()
  global VERBOSE
  VERBOSE = args.verbose
  vprint(f'{args = }')
  
  
  # loading config
  config_path = Path(__file__)
  config_path = config_path.parent / '.config'
  if not config_path.exists():
    cli_generate_default_config(config_path)
    return 0
  
  with open(config_path, 'r') as file:
    config = json.load(file)
  
  
  # create request session
  global sess
  sess = requests.session()
  sess.headers.update({'Authorization': f'Bearer {config["fine-grained-token"]}'})
  
  
  # handle arguments
  try:
    if args.generate_config:
      cli_generate_default_config(config_path)
    elif args.list:
      cli_list_gh_keys(config)
    elif args.create:
      if args.output and len(args.output) > 0:
        out_folder = args.output
      else:
        out_folder = Path('./keys').resolve()
        out_folder.mkdir(parents=True, exist_ok=True)
      save_password = args.password
      save_zip = args.zip
      cli_create_new_gh_key(config, out_folder, save_password, save_zip)
    elif args.remove > 0:
      cli_remove_gh_key(config, args.remove)
    else:
      parser.print_usage()
  except Exception as err:
    print('Exception:', err)
    print(traceback.format_exc())
    return -1
  
  return 0


if __name__ == '__main__':
  main()
