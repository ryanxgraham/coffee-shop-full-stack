import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)
db_drop_and_create_all()

## ROUTES

@app.route('/drinks', methods=['GET'])
def get_drinks():
    drinks = list(map(Drink.short, Drink.query.all()))
    result = {
        "success": True,
        "drinks": drinks
    }
    return jsonify(result)

@app.route('/drinks-detail', methods=['GET'])
@requires_auth('get:drinks-detail')
def get_drinks_detail(payload):
    drinks = list(map(Drink.long, Drink.query.all()))
    result = {
        'success': True,
        'drinks': drinks
    }
    return jsonify(result)

@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def post_drinks(payload):
    new_drink_data = request.get_json()
    new_drink = Drink(title=new_drink_data['title'], recipe = json.dumps(new_drink_data['recipe']))
    new_drink.insert()
    result = {
        "success": True,
        "drinks": new_drink.long()
    }
    return jsonify(result)

@app.route("/drinks/<int:id>", methods=['PATCH'])
@requires_auth("patch:drinks")
def patch_drinks(payload, id):
    new_drink_data = request.get_json()
    if not new_drink_data:
        abort(400)
    change_drink = Drink.query.filter(Drink.id == id).one_or_none()

    new_title = new_drink_data.get('title', None)
    new_recipe = new_drink_data.get('recipe', None)

    if new_title:
        change_drink.title = new_drink_data['title']
    if new_recipe:
        change_drink.recipe = new_drink_data['recipe']

    change_drink.update()

    return jsonify({
    'success': True,
    'drinks': [Drink.long(change_drink)]
    })

@app.route("/drinks/<int:id>", methods=['DELETE'])
@requires_auth("delete:drinks")
def delete_drinks(payload, id):
    if not id:
        abort(422)
    drink_data = Drink.query.filter(Drink.id == id).one_or_none()

    if not drink_data:
        abort(404)

    drink_data.delete()

    result = {
        'success': True,
        'delete': id
    }
    return jsonify(result)

## Error Handling
'''
Example error handling for unprocessable entity
'''
@app.errorhandler(400)
def bad_request(error):
    return jsonify({
                  "success": False,
                  "error": 400,
                  "message": "bad request"
                  }), 400

@app.errorhandler(AuthError)
def auth_error(error):
    return jsonify({
        "success": False,
        "error": error.status_code,
        "message": error.error['code']
        }), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({
                  "success": False,
                  "error": 404,
                  "message": "resource not found"
                  }), 404

@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
                    "success": False,
                    "error": 422,
                    "message": "unprocessable"
                    }), 422
