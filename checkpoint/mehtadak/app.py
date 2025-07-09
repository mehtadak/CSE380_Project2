import sqlite3
import os
import json
from flask import Flask, request
import hashlib
import hmac
import base64

app = Flask(__name__)
db_name = "project2.db"
sql_file = "project2.sql"
db_flag = False


def create_db():
    conn = sqlite3.connect(db_name)
    conn.execute("PRAGMA foreign_keys = ON;")

    with open(sql_file, 'r') as sql_startup:
        init_db = sql_startup.read()
    cursor = conn.cursor()
    cursor.executescript(init_db)
    conn.commit()
    conn.close()
    global db_flag
    db_flag = True
    return conn


def get_db():
    if not db_flag:
        create_db()
    conn = sqlite3.connect(db_name)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@app.route('/', methods=(['GET']))
def index():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM test;")
    result = cursor.fetchall()
    conn.close()

    return result


@app.route('/test_get/<post_id>', methods=(['GET']))
def test_get(post_id):
    result = {}
    result['numbers'] = request.args.get('numbers')
    result['post_id'] = post_id
    result['jwt'] = request.headers['Authorization']

    return json.dumps(result)


@app.route('/test_post', methods=(['POST']))
def test_post():
    result = request.form

    return result


# Function to check if the password is correct or not
# @param password: string, first_name: string, last_name: string, username: string
# @return True or False based on the correctness of the password
def password_check(password, first_name, last_name, username):
    lower_letter_flag = False  # flag to check for a lower case letter
    upper_letter_flag = False  # flag to check for a upper case letter
    number_flag = False  # flag to check for a number
    if (len(password) >= 8):  # checks for the length of the password
        for letter in password:
            if letter.islower():
                lower_letter_flag = True
            elif letter.isupper():
                upper_letter_flag = True
            elif letter.isdigit():
                number_flag = True

    # checks if any of the flags are false
    if (first_name not in password) and (last_name not in password) and (username not in password):
        if lower_letter_flag and upper_letter_flag and number_flag:
            return True

    return False  # returns false if any flags not matched


# Function to decode the header and payload
# @param hp: encoded header or payload
# @return header or payload json
def h_and_p_decoder(hp):
    hp_decoded = base64.urlsafe_b64decode(hp)
    hp_json_str_decoded = hp_decoded.decode()
    hp_json = json.loads(hp_json_str_decoded)
    return hp_json

def signature_verifier(payload, header, signature):
    payload = json.dumps(payload)
    header = json.dumps(header)
    payload = payload.encode()
    header = header.encode()
    key = open("key.txt", "r").read().encode()
    header_encoded = base64.urlsafe_b64encode(header).decode()  # encoding the header
    payload_encoded = base64.urlsafe_b64encode(payload).decode()  # encoding the payload
    message = f"{header_encoded}.{payload_encoded}".encode()  # making the signature
    signature_new = hmac.new(key, message, hashlib.sha256).hexdigest()  # encoding the signature
    return signature == signature_new

# function for the create user endpoint
@app.route('/create_user', methods=(['POST']))
def create_user():
    results = request.form

    # getting all the data from the post request
    first_name = results.get("first_name")
    last_name = results.get("last_name")
    username = results.get("username")
    email_address = results.get("email_address")
    password = results.get("password")
    salt = results.get("salt")
    moderator = results.get("moderator")
    critic = results.get("critic")

    if moderator == "True":
        moderator = 1
    else:
        moderator = 0

    if critic == "True":
        critic = 1
    else:
        critic = 0

    test_data = {
        "first_name": first_name,
        "last_name": last_name,
        "username": username,
        "email_address": email_address,
        "password": password,
        "salt": salt,
        "moderator": moderator,
        "critic": critic
    }

    # checks for the password validation
    password_flag = password_check(password, first_name, last_name, username)

    if not password_flag: # returns json due to password incorrectness
        return json.dumps({"status": 4, "pass_hash": "NULL"})

    # hashing the password
    hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()

    # try and error clause to prevent the db from locking
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Users WHERE username = ? OR email_address = ?;", (username, email_address))
        cursor_return = cursor.fetchone()
        # inserts the records into the db if there is no same username
        if cursor_return is None and password_flag:
            cursor.execute("INSERT INTO Users (first_name, last_name, username, email_address, moderator, critic, hashed_password, salt) VALUES (?,?,?,?,?,?,?,?);",
                           (first_name, last_name, username, email_address, moderator, critic, hashed_password, salt))
            conn.commit()
            conn.close()
            return json.dumps({"status": 1, "pass_hash": hashed_password})

        # if the username exists return a json with a different status code
        elif cursor_return and cursor_return[2] == username:
            conn.close()
            return json.dumps({"status": 2, "pass_hash": "NULL"})

        # if the email exists return a json with a different status code
        elif cursor_return and cursor_return[3] == email_address:
            conn.close()
            return json.dumps({"status": 3, "pass_hash": "NULL"})

    # if anything happens output the error in a json
    except Exception as e:
        return json.dumps({"status": 10, "exception": str(e)})


# function to handle the login endpoint
@app.route('/login', methods=(['POST']))
def login():
    results = request.form

    # gets information from the post request
    username = results.get("username")
    password = results.get("password")

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Users WHERE username = ?;", (username,))
        cursor_results = cursor.fetchone()
        if cursor_results is not None:
            salt = cursor_results[7]# gets the salt from the db
            hashed_pass = hashlib.sha256((password + salt).encode()).hexdigest() # hashes password to check if it is the same
            if hashed_pass == cursor_results[6]:
                key = open("key.txt", "r").read().encode() # reads the file containing the key
                header = json.dumps({"alg":"HS256", "typ":"JWT"}).encode() # making the header
                if cursor_results[4] == 1:
                    payload = json.dumps({"username": username, "moderator": "True"}).encode()
                else:
                    payload = json.dumps({"username":username}).encode() # making the payload
                header_encoded = base64.urlsafe_b64encode(header).decode() # encoding the header
                payload_encoded = base64.urlsafe_b64encode(payload).decode() # encoding the payload
                message = f"{header_encoded}.{payload_encoded}".encode() # making the signature
                signature = hmac.new(key, message, hashlib.sha256).hexdigest() # encoding the signature
                web_token = f"{header_encoded}.{payload_encoded}.{signature}" # generating the web token
                conn.close()
                return json.dumps({"status":1, "jwt":web_token}) # returns successful login json
            else:
                conn.close()
                return json.dumps({"status": 2, "jwt": "NULL"}) # password doesn't match

        conn.close()
        return json.dumps({"status":3, "jwt":"NULL"}) # user not in database json

    except Exception as e:
        conn.close()
        return json.dumps({"status":10, "exception":str(e)})


# function to handle the create_movie endpoint
@app.route('/create_movie', methods=(['GET', 'POST']))
def create_movie():
    genre_dict = None # dictionary to store the genres
    # get all the info from the request
    results = request.form
    title = results.get('title')
    synopsis = results.get('synopsis')
    movie_id = results.get('movie_id')
    genre = results.get('genre')
    if genre is not None:
        genre_dict = json.loads(genre)

    jwt = request.headers['Authorization'] # getting the jwt
    web_token = jwt.split('.')
    header = web_token[0]
    payload = web_token[1]
    signature = web_token[2]

    payload_decoded_json = h_and_p_decoder(payload)
    header_decoded_json = h_and_p_decoder(header)

    sig_flag = signature_verifier(payload_decoded_json, header_decoded_json, signature)
    if not sig_flag:
        return json.dumps({"status":2})
    # checking if the user is a moderator
    if "moderator" not in payload_decoded_json or payload_decoded_json["moderator"] == 0:
        return json.dumps({"status": 2})

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Movies WHERE public_id = ?;", (movie_id,))
        cursor_results = cursor.fetchone()
        # checking if the movie already exists in the db
        if cursor_results is not None:
            conn.close()
            return json.dumps({"status": 2})

        # inserting the movie into the db
        cursor.execute("INSERT INTO Movies(public_id, synopsis, title) VALUES (?,?,?);", (movie_id, synopsis, title))
        if genre_dict is not None:
                for value in genre_dict.values():
                    cursor.execute("INSERT INTO Genres(genre, movie_id) VALUES (?,?);", (value, movie_id))

        conn.commit()
        conn.close()
        return json.dumps({"status": 1})

    except Exception as e:
        return json.dumps({"status": str(e)})


# function to handle the review endpoint
@app.route('/review', methods=(['GET', 'POST']))
def review():
    results = request.form
    rating = int(results.get('rating'))
    text = results.get('text')
    movie_id = results.get('movie_id')
    review_id = results.get('review_id')

    if rating > 5 or rating < 0: # checking if the rating is in the limit
        return json.dumps({"status": "Here"})

    jwt = request.headers['Authorization']
    web_token = jwt.split('.')
    header = web_token[0]
    payload = web_token[1]
    signature = web_token[2]

    payload_decoded_json = h_and_p_decoder(payload) # getting the username from the jwt
    header_decoded_json = h_and_p_decoder(header)
    sig_flag = signature_verifier(payload_decoded_json, header_decoded_json, signature)

    if not sig_flag:
        return json.dumps({"status": "Here too"})

    username = payload_decoded_json["username"]

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Users WHERE username = ?;", (username,))
        cursor_results = cursor.fetchone()
        if cursor_results is None: # checking if the username exists in the db
            conn.close()
            return json.dumps({"status": "Maybe"})

        cursor.execute("SELECT * FROM Movies WHERE public_id = ?", (movie_id,))
        cursor_results = cursor.fetchone()
        if cursor_results is None: # checking if the movie exists in the db
            conn.close()
            return json.dumps({"status": "Maybe"})

        # inserting the review
        cursor.execute("INSERT INTO Reviews(review_id, rating, review_text, movie_id, user) VALUES(?,?,?,?,?);", (review_id, rating, text, movie_id, username))
        conn.commit()
        conn.close()
        return json.dumps({"status": 1})

    except Exception as e:
        return json.dumps({"status": str(e)})


# function to handle the view_movie endpoint
@app.route('/view_movie/<post_id>', methods=(["GET"]))
def view_movie(post_id):
    result = {}  # creating a dict to store the parameters
    result['title'] = request.args.get('title')
    result['synopsis'] = request.args.get('synopsis')
    result['genre'] = request.args.get('genre')
    result['critic'] = request.args.get('critic')
    result['audience'] = request.args.get('audience')
    result['reviews'] = request.args.get('reviews')
    result['jwt'] = request.headers['Authorization']
    result['id'] = post_id

    web_token = result["jwt"].split('.')
    header = web_token[0]
    payload = web_token[1]
    signature = web_token[2]

    payload_decoded_json = h_and_p_decoder(payload)  # getting the username from the jwt
    header_decoded_json = h_and_p_decoder(header)
    sig_flag = signature_verifier(payload_decoded_json, header_decoded_json, signature)

    if not sig_flag:
        return json.dumps({"status": 2, "data": "NULL"})

    # lists to store the genres and reviews respectively
    genre_list = list()
    review_list = list()

    data = dict() # dictionary to store all the requested data

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Movies WHERE public_id = ?", (result['id'],))
        cursor_results = cursor.fetchone()
        if cursor_results is None: # checking if the movie exists in the db
            conn.close()
            return json.dumps({"status": 2, "data": "NULL"})

        for keys, values in result.items():
            if values is None: # checking if the parameter was requested
                continue

            if keys == "genre": # handling the genre parameter requested
                cursor.execute("SELECT genre FROM Genres WHERE movie_id = ?;", (result['id'],))
                cursor_results = cursor.fetchall()
                if cursor_results is None:
                    continue

                genres = cursor_results
                for genre in genres:
                    genre_list.append(genre[0]) # appending all the genres to the genre list

                data["genre"] = genre_list

            elif keys == "reviews": # handling the reviews parameter requested
                cursor.execute("SELECT user, rating, review_text FROM Reviews WHERE movie_id = ?;", (result['id'],))
                cursor_results = cursor.fetchall()
                if cursor_results is None:
                    continue

                all_reviews = cursor_results
                for review in all_reviews:
                    # appending the review dict to the review list
                    review_list.append({"user": review[0], "rating": str(review[1]), "text": review[2]})

                data["reviews"] = review_list

            elif keys == "audience": # handling the critic and audience parameter requested
                cursor.execute("SELECT AVG(rating) as avg FROM Reviews INNER JOIN Users ON Reviews.user = Users.username WHERE Users.critic = ? AND Reviews.movie_id = ?; ", (0, result['id']))

                rate = cursor.fetchone()
                if rate is None or rate[0] is None:
                    data[keys] = "{:.2f}".format(0.00)
                else:
                    data[keys] = "{:.2f}".format(rate[0])

            elif keys == "critic" : # handling the critic and audience parameter requested
                cursor.execute("SELECT AVG(rating) as avg FROM Reviews INNER JOIN Users ON Reviews.user = Users.username WHERE Users.critic = ? AND Reviews.movie_id = ?; ", (1, result['id']))

                rate = cursor.fetchone()
                if rate is None or rate[0] is None:
                    data[keys] = "{:.2f}".format(0.00)
                else:
                    data[keys] = "{:.2f}".format(rate[0])

            elif keys == "title": # handling the title and synopsis parameter requested
                cursor.execute("SELECT title FROM Movies WHERE public_id = ?;", (result["id"],))
                titleORsynopsis = cursor.fetchall()
                data[keys] = titleORsynopsis[0][0]

            elif keys == "synopsis": # handling the title and synopsis parameter requested
                cursor.execute("SELECT synopsis FROM Movies WHERE public_id = ?;", (result["id"],))
                titleORsynopsis = cursor.fetchall()
                data[keys] = titleORsynopsis[0][0]

        conn.commit()
        conn.close()
        return json.dumps({"status": 1, "data": data})

    except Exception as e:
        return json.dumps({"status": 10, "data": str(e)})


# function to handle the search endpointz
@app.route('/search', methods=(["GET"]))
def search():
    result = {}
    result["feed"] = request.args.get("feed")
    result["genre"] = request.args.get("genre")
    result['jwt'] = request.headers['Authorization']

    data = dict() # dictionary to store all the requested data

    web_token = result["jwt"].split('.')
    header = web_token[0]
    payload = web_token[1]
    signature = web_token[2]

    payload_decoded_json = h_and_p_decoder(payload)  # getting the username from the jwt
    header_decoded_json = h_and_p_decoder(header)
    sig_flag = signature_verifier(payload_decoded_json, header_decoded_json, signature)

    if not sig_flag:
        return json.dumps({"status": 2, "data":"NULL"})

    try:
        conn = get_db()
        cursor = conn.cursor()
        if result["feed"] is not None: # handles if feed is requested
            # sorting the results by the 5 recent movies in the db
            cursor.execute("SELECT * FROM Movies ORDER BY id DESC LIMIT 5;")
            cursor_results = cursor.fetchall()
            if cursor_results is None:
                conn.close()
                return json.dumps({"status": 2, "data": "NULL"})

            temp_dict = dict()
            for movie in cursor_results:
                temp_dict["title"] = movie[2]
                temp_dict["synopsis"] = movie[1]
                public_id = movie[0]

                genre_list = list()
                cursor.execute("SELECT genre FROM Genres WHERE movie_id = ?;", (public_id,))
                cursor_results = cursor.fetchall()

                genres = cursor_results
                for genre in genres:
                    genre_list.append(genre[0])  # appending all the genres to the genre list

                temp_dict["genre"] = genre_list

                cursor.execute("SELECT user, rating, review_text FROM Reviews WHERE movie_id = ?;", (public_id,))
                cursor_results = cursor.fetchall()

                review_list = list()
                all_reviews = cursor_results
                for review in all_reviews:
                    # appending the review dict to the review list
                    review_list.append({"user": review[0], "rating": str(review[1]), "text": review[2]})

                temp_dict["reviews"] = review_list

                cursor.execute(
                    "SELECT AVG(rating) as avg FROM Reviews INNER JOIN Users ON Reviews.user = Users.username WHERE Users.critic = ? AND Reviews.movie_id = ?; ",
                    (0, public_id))

                rate = cursor.fetchone()
                if rate is None or rate[0] is None:
                    temp_dict["audience"] = "{:.2f}".format(0.00)
                else:
                    temp_dict["audience"] = "{:.2f}".format(rate[0])

                cursor.execute(
                    "SELECT AVG(rating) as avg FROM Reviews INNER JOIN Users ON Reviews.user = Users.username WHERE Users.critic = ? AND Reviews.movie_id = ?; ",
                    (1, public_id))

                rate = cursor.fetchone()
                if rate[0] is None:
                    temp_dict["critic"] = "{:.2f}".format(0.00)
                else:
                    temp_dict["critic"] = str(rate[0])

                data[public_id] = temp_dict

        elif result["genre"] is not None: # handles if movies by genre is requested
            cursor.execute("SELECT * FROM Movies LEFT JOIN Genres ON Movies.public_id = Genres.movie_id WHERE Genres.genre = ?;", (result["genre"],))
            cursor_results = cursor.fetchall()
            if cursor_results is None:
                conn.close()
                return json.dumps({"status": 2, "data": "NULL"})

            temp_dict = dict()
            for movie in cursor_results:
                temp_dict["title"] = movie[2]
                temp_dict["synopsis"] = movie[1]
                public_id = movie[0]

                genre_list = list()
                cursor.execute("SELECT genre FROM Genres WHERE movie_id = ?;", (public_id,))
                cursor_results = cursor.fetchall()

                genres = cursor_results
                for genre in genres:
                    genre_list.append(genre[0]) # appending all the genres to the genre list

                temp_dict["genre"] = genre_list

                cursor.execute("SELECT user, rating, review_text FROM Reviews WHERE movie_id = ?;", (public_id,))
                cursor_results = cursor.fetchall()

                review_list = list()
                all_reviews = cursor_results
                for review in all_reviews:
                    # appending the review dict to the review list
                    review_list.append({"user": review[0], "rating": str(review[1]), "text": review[2]})

                temp_dict["reviews"] = review_list

                cursor.execute("SELECT AVG(rating) as avg FROM Reviews INNER JOIN Users ON Reviews.user = Users.username WHERE Users.critic = ? AND Reviews.movie_id = ?; ", (0, public_id))

                rate = cursor.fetchone()
                if rate is None or rate[0] is None:
                    temp_dict["audience"] = "{:.2f}".format(0.00)
                else:
                    temp_dict["audience"] = "{:.2f}".format(rate[0])

                cursor.execute("SELECT AVG(rating) as avg FROM Reviews INNER JOIN Users ON Reviews.user = Users.username WHERE Users.critic = ? AND Reviews.movie_id = ?; ", (1, public_id))

                rate = cursor.fetchone()
                if rate[0] is None:
                    temp_dict["critic"] = "{:.2f}".format(0.00)
                else:
                    temp_dict["critic"] = str(rate[0])

                data[public_id] = temp_dict
        else:
            conn.close()
            return json.dumps({"status": 2, "data": "NULL"})

        conn.commit()
        conn.close()
        return json.dumps({"status": 1, "data": data})

    except Exception as e:
        return json.dumps({"status": 10, "data": str(e)})


# function to handle the delete function
@app.route('/delete', methods=(['GET', 'POST']))
def delete():
    result = request.form
    username = result.get("username")
    review_id = result.get("review_id")
    jwt = request.headers["Authorization"]

    web_token = jwt.split('.')
    header = web_token[0]
    payload = web_token[1]
    signature = web_token[2]

    payload_decoded_json = h_and_p_decoder(payload)  # getting the username from the jwt
    header_decoded_json = h_and_p_decoder(header)
    sig_flag = signature_verifier(payload_decoded_json, header_decoded_json, signature)

    if not sig_flag:
        return json.dumps({"status": 2})

    payload = payload_decoded_json

    try:
        mod_flag = False # flag to check if the user is a moderator
        if "moderator" in payload.keys() and payload["moderator"] == "True":
            mod_flag = True

        conn = get_db()
        cursor = conn.cursor()

        if username is not None: # if the user requests to be deleted
            if username != payload["username"]:
                conn.close()
                return json.dumps({"status": 2})

            cursor.execute("SELECT * FROM Users WHERE username = ?;", (username,))
            cursor_results = cursor.fetchone()
            if cursor_results is None:
                conn.close()
                return json.dumps({"status": 2})

            cursor.execute("DELETE FROM Users WHERE username = ?;", (username,))
            conn.commit()
            conn.close()
            return json.dumps({"status": 1})

        elif review_id is not None: # if a review is being deleted
            cursor.execute("SELECT * FROM Reviews WHERE review_id = ?;", (review_id,))
            cursor_results = cursor.fetchone()
            if cursor_results is None:
                conn.close()
                return json.dumps({"status": 2})

            if mod_flag:
                cursor.execute("DELETE FROM Reviews WHERE review_id = ?;", (review_id,))

            else:
                if cursor_results[4] != payload["username"]:
                    conn.close()
                    return json.dumps({"status": 2})

                cursor.execute("DELETE FROM Reviews WHERE review_id = ?;", (review_id,))

            conn.commit()
            conn.close()
            return json.dumps({"status": 1})

        else:
            conn.close()
            return json.dumps({"status": 2})

    except Exception as e:
        return json.dumps({"error": str(e)})


# function that handles the clear endpoint
@app.route('/clear', methods=(['GET']))
def clear():
    try: # removes the db and changes the database flag to false
        os.remove(db_name)
        global db_flag
        db_flag = False

    # error handling if the file does not exist
    except Exception as e:
        return json.dumps({"status": 10, "error":str(e)})

    return None