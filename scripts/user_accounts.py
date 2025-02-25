# user_accounts.py

import pwd

def get_user_accounts():
    # get users
    # get list od dicts
    accounts = []
    for user in pwd.getpwall():
        account = {
            "username": user.pw_name,
            "uid": user.pw_uid,
            "gid": user.pw_gid,
            "home": user.pw_dir,
            "shell": user.pw_shell,
            "gecos": user.pw_gecos,
        }
        accounts.append(account)
    return accounts
