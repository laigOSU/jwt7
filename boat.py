from flask import Blueprint, request
from flask import request
from google.cloud import datastore
import json
import constants

from requests_oauthlib import OAuth2Session
from google.oauth2 import id_token
from google.auth import crypt
from google.auth import jwt
from google.auth.transport import requests
import jwt

client = datastore.Client()

bp = Blueprint('boat', __name__, url_prefix='/boats')

@bp.route('', methods=['POST','GET'])
def boats_get_post():
    #---- POST: CREATE A NEW BOAT ----#
    if request.method == 'POST':
        jwt_param = request.args.get("jwt")
        if jwt_param is None:
            print("no params")
            return("Missing/Invalid JWT", 401)
        else:
            print("yes params")
            # Get the JWT info
            req = requests.Request()
            id_info = id_token.verify_oauth2_token(
            request.args['jwt'], req, constants.client_id)
            print("req is: ", req)
            print("User's email is: id_info[email] = ", id_info['email'])
            # payload = jwt.decode(encoded, client_secret, algorithms='HS256')
            # print("jwt is: ", payload)

            # Make a new boat
            content = request.get_json()
            new_boat = datastore.entity.Entity(key=client.key(constants.boats))
            new_boat.update({"name": content["name"], 'type': content['type'], 'length': content['length'], 'owner': id_info['email']})
            client.put(new_boat)

            # Check if user['email'] already exists
            query = client.query(kind=constants.users)
            query.add_filter('email', '=', id_info['email'])
            queryresults = list(query.fetch())
            if (queryresults):
                print("Email exists in user DB")
            else:
                print("Email does not yet exist in user DB")
                new_user = datastore.entity.Entity(key=client.key(constants.users))
                new_user.update({"email": id_info['email']})
                client.put(new_user)

            # If user doesn't already exist, create new user entity

            return (str(new_boat.key.id), 201)
            # return repr(id_info) + "<br><br> the user is: " + id_info['email']



    #---- GET: VIEW ALL BOATS ----#
    elif request.method == 'GET':
        query = client.query(kind=constants.boats)
        results = list(query.fetch())
        for e in results:
            e["id"] = e.key.id
            # url = "http://localhost:8080/boats/" + str(e.key.id)
            url = constants.appspot_url + constants.boats + "/" + str(e.key.id)
            e["boat_url"] =url
        return json.dumps(results)

    else:
        return 'Method not recognized'

@bp.route('/<id>', methods=['PUT','DELETE','GET'])
def boats_put_delete_get(id):
    #---- PUT: MODIFY A SPECIFIC BOAT ----#
    if request.method == 'PUT':
        content = request.get_json()
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        boat.update({"name": content["name"], 'type': content['type'], 'length': content['length']})
        client.put(boat)
        return ('',200)

    #---- DELETE: REMOVE A SPECIFIC BOAT ----#
    elif request.method == 'DELETE':
        # Check if JWT missing/invalid
        jwt_param = request.args.get("jwt")

        if jwt_param is None:
            print("no params")
            return("Missing/Invalid JWT", 401)

        else:
            # Get the boat
            boat_key = client.key(constants.boats, int(id))
            boat = client.get(key=boat_key)

            # Get the boat's owner
            boat_owner = boat['owner']
            print("boat_owner is: ", boat_owner)


            # Confirm user is authorized to delete
            req = requests.Request()

            id_info = id_token.verify_oauth2_token(
            request.args['jwt'], req, constants.client_id)
            if(id_info['email'] == boat_owner):

                # Check if boat is docked in a slip --> if boat_id == slip["current_boat"]
                # Get that slip
                query = client.query(kind=constants.slips)
                query.add_filter('current_boat', '=', id)
                queryresults = list(query.fetch())
                print("queryresults is: ", queryresults)
                for e in queryresults:
                    print("number is: ", e["number"])
                    print("current_boat is: ", e["current_boat"])
                    print("slip id is: ", e.key.id)
                    slip_id = e.key.id

                    slip_key = client.key(constants.slips, slip_id)
                    slip = client.get(key=slip_key)
                    slip["current_boat"] = "null"
                    slip["arrival_date"] = "null"
                    client.put(slip)
                # client.delete(boat_key)

                return ('Okay deleting',200)
            else:
                return('Not authorized to delete boat owned by another', 403)

    #---- GET: VIEW A SPECIFIC BOAT ----#
    elif request.method == 'GET':
        query = client.query(kind=constants.boats)
        first_key = client.key(constants.boats,int(id))
        query.key_filter(first_key,'=')
        results = list(query.fetch())
        for e in results:
            e["id"] = id
            # url = "http://localhost:8080/boats/" + id
            url = constants.appspot_url + constants.boats + "/" + id
            e["boat_url"] =url
        return json.dumps(results)


    else:
        return 'Method not recognized'
