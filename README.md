# Github ssh key manager

A simple utility to manage temporary ssh keys in your github account.

When you need to access any github repository via ssh but don't want to copy your master ssh key to your working environment, you can use this tool to create a temporary ssh key, and delete it later on.

# Requirements

## Python >= 3.8

## Install required packages
```sh
pip install -r requirements.txt
```

# Configuration

This utility is base on [github's api for managing ssh key](https://docs.github.com/en/rest/users/keys?apiVersion=2022-11-28)

You need to [generate a fine-grained token](https://github.com/settings/personal-access-tokens/new) to use the api.

While generating the token, make sure you add `Git SSH keys` permission with `Read and write` access, so this utility can function correctly.

After you generate your fine-grained token, copy the token and fill it into the configuration file (`.config`) for this utility.

You have two ways to create a config file for this utility:
1. The utility will create a `.config` file when first time running it.
2. You can use flag `-g` or `--generate_config` to create a `.config` file. **Note that this flag will overwrite exising config file.**


# Usage & Examples

To see usage and help message:

```sh
python ghssh_key_mgr.py -h
```

Some examples:

1. Generate a `.config` file for the utility. **This flag will overwrite existing `.config` file**
```sh
python ghssh_key_mgr.py -g
```

2. List ssh keys in your github account
```sh
python ghssh_key_mgr.py -l
```

3. Create a new ssh key and upload it to your github account
```sh
# output ssh keys to "./keys" folder by default
python ghssh_key_mgr.py -c

# set output folder to "./test"
python ghssh_key_mgr.py -c -o "./test"
```

4. Remove a ssh key specified by input id from your github account. You can get the key id from listing keys.
```sh
python ghssh_key_mgr.py -r KEY_ID
```
