from flask import Blueprint, render_template
from scripts.user_accounts import get_user_accounts

bp = Blueprint('accounts', __name__, url_prefix='/accounts')

@bp.route('/')
def index():
    accounts_list = get_user_accounts()
    return render_template('accounts/index.html', accounts=accounts_list)