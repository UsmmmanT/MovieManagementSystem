import tmdbsimple as tmdb
from flask import Flask, render_template, request, redirect, url_for, session,jsonify
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
import pg8000
import ssl
import secrets
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd
import traceback

tmdb.API_KEY = "4328059314cf1e2d573176490f1c69a3"  #TMDB API key

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

@app.before_request
def clear_template_cache():
    app.jinja_env.cache = {}

#Database Utility Functions
def get_db_connection():
    # Create an SSL context
    ssl_context = ssl.create_default_context()

    conn = pg8000.connect(
        database='hujdb',
        user='hujdb_owner',
        password='0gxdDPcj9NfG',
        host='ep-proud-term-a5qyatn7.us-east-2.aws.neon.tech',
        port=5432,                # Ensure port is an integer
        ssl_context=ssl_context   # Use ssl_context instead of ssl
    )
    return conn

def execute_db_query(query, params=None, fetch_one=False, fetch_all=False):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if params is not None:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        if fetch_one:
            return cursor.fetchone()
        elif fetch_all:
            return cursor.fetchall()
        conn.commit()
        return True
    except pg8000.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


#Utility Functions For Movies   
def fetch_movie_details(movie_id):
    """Fetch detailed movie data along with crew info from TMDB API."""
    try:
        movie = tmdb.Movies(movie_id)
        details = movie.info()  # Fetch general movie details
        credits = movie.credits()  # Fetch credits, including cast and crew

        # Extract crew information
        crew = [
            {"name": member.get("name"), "job": member.get("job"), "department": member.get("department")}
            for member in credits.get("crew", [])
        ]

        return {
            "movie_id": movie_id,
            "title": details.get("title"),
            "release_year": details.get("release_date", "").split("-")[0],
            "poster_url": f"https://image.tmdb.org/t/p/w500{details.get('poster_path')}" if details.get('poster_path') else "",
            "popularity": details.get("popularity"),
            "genres": [genre.get("name") for genre in details.get("genres", [])],
            "overview": details.get("overview"),
            "crew": crew,  # Include crew information
        }
    except Exception as e:
        print(f"Error fetching movie details: {e}")
        return {}
   
def fetch_tv_details(tv_id):
    """Fetch detailed TV show data from TMDB API."""
    try:
        tv_show = tmdb.TV(tv_id)
        details = tv_show.info()

        return {
            "movie_id": tv_id,
            "title": details.get("name"),  # TV shows use "name" instead of "title"
            "release_year": details.get("first_air_date", "").split("-")[0],
            "poster_url": f"https://image.tmdb.org/t/p/w500{details.get('poster_path')}" if details.get('poster_path') else "",
            "popularity": details.get("popularity"),
            "genres": [genre.get("name") for genre in details.get("genres", [])],
            "overview": details.get("overview"),
        }
    except Exception as e:
        print(f"Error fetching TV show details: {e}")
        return {}

def fetch_movie_data(query, page=1):
    """Fetch movie, TV show, and person data from TMDB API for a specific page."""
    try:
        search = tmdb.Search()
        response = search.multi(query=query, page=page)  # Using multi search
        results = response.get('results', [])
        filtered_results = []

        for result in results:
            media_type = result.get('media_type')

            # For Movies
            if media_type == 'movie':
                filtered_results.append({
                    "id": result.get("id"),  # Include movie ID
                    "title": result.get("title"),
                    "media_type": "Movie",
                    "release_date": result.get("release_date"),
                    "poster_url": f"https://image.tmdb.org/t/p/w500{result.get('poster_path')}" if result.get('poster_path') else "",
                })

            # For TV Shows
            elif media_type == 'tv':
                filtered_results.append({
                    "id": result.get("id"),  # Include TV show ID
                    "title": result.get("name"),
                    "media_type": "TV Show",
                    "release_year": result.get("first_air_date", "").split("-")[0],  # Extract year
                    "poster_url": f"https://image.tmdb.org/t/p/w500{result.get('poster_path')}" if result.get('poster_path') else "",
                })

            # For People
            elif media_type == 'person':
                known_for_titles = [item.get("title") or item.get("name") for item in result.get("known_for", [])]
                filtered_results.append({
                    "id": result.get("id"),  # Include person ID
                    "name": result.get("name"),
                    "media_type": "Person",
                    "known_for": known_for_titles,
                    "profile_pic_url": f"https://image.tmdb.org/t/p/w500{result.get('profile_path')}" if result.get('profile_path') else "",
                })

        return filtered_results

    except Exception as e:
        print(f"Error fetching data from TMDB: {e}")
        return []
    
def get_recommended_movie_details(user_id):
    """
    Fetches detailed movie information for the recommended movies of a user.

    Parameters:
        user_id (int): The ID of the user.

    Returns:
        list: A list of dictionaries containing movie details, or an empty list if no recommendations exist.
    """
    # Call get_movie_recommendations and parse its response
    response, status_code = get_movie_recommendations(user_id)

    # Check if the response contains recommendations
    if status_code == 200:  # HTTP 200 means success
        # Parse the JSON response to extract movie IDs
        response_data = response.get_json()  # Use `get_json` to parse the response body
        recommended_movie_ids = response_data.get("recommended_movies", [])

        # Fetch details for each movie ID
        movie_details_list = [
            fetch_movie_details(movie_id) for movie_id in recommended_movie_ids[:10]
        ]

        return movie_details_list
    else:
        # If no recommendations, return an empty list
        return []

def popular():
    """Fetches popular movies from TMDB API."""
    try:
        # Fetch popular movies from TMDB API
        movies_t = tmdb.Movies(671)  # Assuming 671 is a valid movie ID for the TMDB API
        popular_movies = movies_t.popular()

        # Extract the 'results' key from the response, which is a list of movie dictionaries
        movies = popular_movies.get('results', [])

        # Filter and process the movie data
        filtered_movies = [
            { 
                "movie_id": int(movie.get("id")) if movie.get("id") else None,  # Check if 'id' is not None before casting
                "title": movie.get("title"),
                "release_date": movie.get("release_date", "").split("-")[0],  # Get the release year
                "backdrop_url": f"https://image.tmdb.org/t/p/w500{movie.get('backdrop_path')}" if movie.get('backdrop_path') else "",
                "poster_url": f"https://image.tmdb.org/t/p/w500{movie.get('poster_path')}" if movie.get('poster_path') else "",
            }
            for movie in movies  # Iterate over each movie dictionary
        ]

        
        return filtered_movies

    except Exception as e:
        print(f"Error fetching popular movies: {e}")
        return []


#Routing For Index Page
@app.route('/')
def index():
    movies_list = popular()  # Get popular movies
    recommended_movies = []
    if 'user_id' in session:
        user_id = session['user_id']
        recommended_movies = get_recommended_movie_details(user_id)  # Fetch recommended movie details

    return render_template(
        'index.html',
        movies=movies_list,
        recommended_movies=recommended_movies
    )

#Route And Function For Session_User
@app.route('/review1', endpoint='review1')
def get_reviews_by_user(): 
    # Check if the user is logged in
    if not session.get('logged_in'):
        # Render the template with a message to sign in
        return render_template('review1.html', reviews=None, logged_in=False)

    # Query to fetch reviews for the logged-in user
    query = '''SELECT review_id, user_id, movie_id, tv_id, rating, review_text, 
                      allow_interaction, netvotes, created_at, updated_at 
               FROM reviews 
               WHERE user_id = %s'''

    try:
        reviews = execute_db_query(query, (session['user_id'],), fetch_all=True)
    except KeyError:
        return render_template('review1.html', reviews=None, logged_in=False)

    # Check if there are no reviews
    if not reviews:
        return render_template('review1.html', reviews=[], logged_in=True)

    # Initialize an empty list to store the formatted reviews
    reviews_list = []

    # Iterate through the fetched reviews and format them
    for review in reviews[:10]:
        movie_detail = fetch_movie_details(review[2])
        
        reviews_list.append({
            "poster_path": movie_detail.get("poster_url"),
            "title": movie_detail.get("title"),
            "release_year": movie_detail.get("release_year"),
            "review_id": review[0],
            "user_id": session['user_id'],
            "movie_id": review[2],
            "tv_id": review[3],
            "rating": review[4],
            "review_text": review[5],
            "allow_interaction": review[6],
            "netvotes": review[7],
            "created_at": review[8].strftime("%d-%b-%Y") if review[8] else None,
            "updated_at": review[9].strftime("%d-%b-%Y") if review[9] else None
        })

    # Render the template with the reviews
    return render_template('review1.html', reviews=reviews_list, logged_in=True)


# Route for Search Page
@app.route('/search', methods=['GET', 'POST'])
def search():  
    return render_template('search.html')

#After Search The Movies.html is Rendered to Display the query result of Search
@app.route('/movies')
def movies():
    query = request.args.get('movie')
    if query:
        # Fetch movie data
        movie_data = fetch_movie_data(query)
        
        # Fetch user data using the provided function
        user_data = get_user_info(query) 
        
        # Pass both movies and users to the template
        return render_template('movies.html', movies=movie_data, users=user_data)
    else:
        # When no query is provided, send empty lists for both movies and users
        return render_template('movies.html', movies=[], users=[])

# Route for Sign In Page
@app.route('/signin', methods=['GET', 'POST'])
def signin():
   
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Check if the user exists
            cursor.execute('''
                SELECT hashed_password FROM user_security 
                WHERE username = (SELECT username FROM users WHERE username = %s)
            ''', (username,))

            result = cursor.fetchone()
            cursor.execute("SELECT user_id FROM users WHERE username = %s", (username,))
            user_result = cursor.fetchone()
        
            if user_result is None:
             return jsonify({"message": "User not found."}), 404
        
            user_id = user_result[0]  # Extract the user ID
            if result:
                hashed_password = result[0]

                # Verify the password
                if check_password_hash(hashed_password, password):
                    # Successful login
                    session['username'] = username  # Store username in session
                    session['logged_in'] = True      # Set logged_in to True
                    session['user_id']=user_id
                    return redirect(url_for('index'))
                else:
                    return "Invalid password. Please try again."
            else:
                return "Username does not exist."

        except pg8000.Error as e:
            print(f"An error occurred: {e}")
            return "An error occurred during sign-in."
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template('signin.html')

# Route for displaying the signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Hash the password for security
        hashed_password = generate_password_hash(password)

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Insert into users table
            cursor.execute('''
                INSERT INTO users (username, email) 
                VALUES (%s, %s) RETURNING user_id
            ''', (username, email))

            # Fetch the newly created user_id
            user_id = cursor.fetchone()[0]

            # Now insert into user_security table
            cursor.execute('''
                INSERT INTO user_security (username, hashed_password) 
                VALUES (%s, %s)
            ''', (username, hashed_password))
            session['username'] = username  # Store username in session
            session['logged_in'] = True 
            
            conn.commit()
            return redirect(url_for('index'))
        except pg8000.Error as e:
            # Handle any pg8000 error, including unique constraint violations
            print(f"An error occurred: {e}")
            return "An error occurred during sign-up."
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template('signup.html')

#log out Functionality
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('logged_in', None)  # Remove the logged-in session variable
    return jsonify({"message": "Logged out successfully."}), 200



#Specific Movie or Tv Show Details
@app.route('/movies/<int:movie_id>/<media_type>')
def media_detail(media_type, movie_id):
    if media_type == "movie":
        media_info = fetch_movie_details(movie_id)
        return render_template('movie_detail.html', movie=media_info)
    elif media_type == "tv":
        media_info = fetch_tv_details(movie_id)
        return render_template('movie_detail.html', movie=media_info,movie_type=media_type)
    else:
        return "Media type not supported", 400
@app.route('/add_to_watchlist', methods=['POST'])
#Function for add to watchlist for any specific movie or tvshow
def add_to_watchlist():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401  # Unauthorized

    user_id = session['user_id']
    data = request.get_json()
    movie_id = data.get('movie_id')

    if not movie_id:
        return jsonify({'message': 'Movie ID is required'}), 400  # Bad Request

    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Retrieve the list_id for the user's watchlist
        cursor.execute("""
            SELECT list_id
            FROM lists
            WHERE user_id = %s AND list_type = %s
        """, (user_id, 'watchlist'))
        result = cursor.fetchone()

        if not result:
            return jsonify({'message': 'Watchlist not found for the user'}), 404  # Not Found

        list_id = result[0]

        # Insert the movie_id into the list_movies table
        cursor.execute("""
            INSERT INTO list_items (list_id, movie_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
        """, (list_id, movie_id))

        conn.commit()
        return jsonify({'message': 'Movie added to watchlist successfully!'}), 200

    except Exception as e:
        print("Error:", e)
        conn.rollback()
        return jsonify({'message': 'An error occurred while adding to the watchlist'}), 500

    finally:
        cursor.close()
        conn.close()


#Function And Render Template For Session User
@app.route('/curr_user_detail', methods=['GET', 'POST'])
#Render Template For Current_user
def get_curr_user_detail():
    if 'user_id' not in session or not session.get('logged_in'):
        return redirect(url_for('signin'))  # Redirect to login if the user is not logged in

    # Fetch logged-in user's details
    user_detail = get_user_info_exact(session['user_id'])
    friends=get_friends()
   
    if not user_detail:
        return "User not found", 404

    # Fetch pending friend requests for the logged-in user (requestee)
    friend_requests_query = '''
        SELECT request_id, requester_id, status FROM friendship_requests 
        WHERE requestee_id = %s AND status = 'pending'
    '''
    friend_requests = execute_db_query(friend_requests_query, (session['user_id'],), fetch_all=True)


    # Render the profile and pending friend requests
    return render_template('curr_user.html', user=user_detail, friend_requests=friend_requests,friends=friends)

def get_user_lists_any_user(user_id):
    """
    Fetch all details for user lists based on a specific user ID.
    """
    query = """
        SELECT list_id, user_id, list_title, description, netvotes, created_at, updated_at,list_type
        FROM lists WHERE user_id = %s
    """
    params = (user_id,)
    
    # Fetch results from the database
    result = execute_db_query(query=query, params=params, fetch_all=True)
    
    # Format the result as a list of dictionaries
    formatted_result = [{
        "list_id": row[0],
        "user_id": row[1],
        "list_title": row[2],
        "description": row[3],
        "netvotes": row[4],
        "created_at": row[5],
        "updated_at": row[6],
        "list_type":row[7]
    } for row in result]

    return formatted_result


def get_user_info_exact(user_id):
    """
    Fetch user information from the user table based on the user_id.
    
    Args:
        user_id (int): The user_id to search for in the database.

    Returns:
        list: A list of dictionaries containing 'user_id', 'user_name', and 'email', 
              or None if no user is found.
    """
    query = """
    SELECT user_id, username, email 
    FROM users 
    WHERE user_id = %s;
    """
    
    # Parameters for exact matching
    params = (user_id,)
 
    
    try:
        # Assuming execute_db_query is a utility function for executing database queries
        result = execute_db_query(query, params, fetch_all=True)
      
        
        if result:
            # Structure each tuple as a dictionary and return as a list
            users = [
                {
                    'user_id': row[0],   # user_id is at index 0
                    'user_name': row[1], # username is at index 1
                    'email': row[2]      # email is at index 2
                }
                for row in result
            ]
            return users
        else:
            return None  # No user found matching the query
    except Exception as e:
        print(f"Error fetching user info: {e}")
        return None

@app.route('/accept_friend_request/<int:request_id>', methods=['POST'])
def accept_friend_request(request_id):
    if 'user_id' not in session or not session.get('logged_in'):
        return redirect(url_for('login'))  # Redirect to login if the user is not logged in

    # Get the request details
    get_request_query = '''
        SELECT requester_id, requestee_id FROM friendship_requests WHERE request_id = %s AND status = 'pending'
    '''
    request = execute_db_query(get_request_query, (request_id,), fetch_one=True)

    if not request:
        return jsonify({"error": "Invalid or expired friend request"}), 400

    requester_id = request[0]
    requestee_id = request[1]

    # Update the friend request status to "accepted"
    update_request_query = '''
        UPDATE friendship_requests SET status = 'accepted' WHERE request_id = %s
    '''
    execute_db_query(update_request_query, (request_id,))

    # Insert both users into the friends table
    insert_friend_query = '''
        INSERT INTO friends (user_id_1, user_id_2) VALUES (%s, %s), (%s, %s)
    '''
    execute_db_query(insert_friend_query, (requester_id, requestee_id, requestee_id, requester_id))

    return jsonify({"message": "Friend request accepted successfully!"}), 200

def get_friends():
    if 'user_id' not in session or not session.get('logged_in'):
        return redirect(url_for('login'))  # Redirect to login page if not logged in
    
    user_id = session['user_id']
    
    # Query to fetch all friends for the logged-in user
    get_friends_query = '''
        SELECT user_id_1, user_id_2 
        FROM friends 
        WHERE user_id_1 = %s OR user_id_2 = %s
    '''
    
    # Execute the query
    friends = execute_db_query(get_friends_query, (user_id, user_id), fetch_all=True)
    
    # Prepare the list of friends
    friend_ids = []
    for friend in friends:
        if friend[0] != user_id:
            friend_ids.append(friend[0])
        else:
            friend_ids.append(friend[1])
    
    # Fetch user details for each friend
    friends_details = []
    for friend_id in friend_ids:
        friend_detail = get_user_info_exact(friend_id)  # Assuming `get_user_info_exact` retrieves user info
        if friend_detail:
            friends_details.append(friend_detail)
    
    # Flatten the friends_details if it's nested
    flat_friends_details = [friend for sublist in friends_details for friend in sublist]
    
    return flat_friends_details

@app.route('/delete_friend_request/<int:request_id>', methods=['POST'])
def delete_friend_request(request_id):
    if 'user_id' not in session or not session.get('logged_in'):
        return redirect(url_for('login'))  # Redirect to login if the user is not logged in

    # Verify if the request exists and is pending
    get_request_query = '''
        SELECT requester_id, requestee_id FROM friendship_requests WHERE request_id = %s AND status = 'pending'
    '''
    request = execute_db_query(get_request_query, (request_id,), fetch_one=True)

    if not request:
        return jsonify({"error": "Invalid or expired friend request"}), 400

    # Delete the friend request
    delete_request_query = '''
        DELETE FROM friendship_requests WHERE request_id = %s
    '''
    execute_db_query(delete_request_query, (request_id,))

    return jsonify({"message": "Friend request deleted successfully!"}), 200

@app.route('/delete_friend/<int:friend_id>', methods=['POST'])
def delete_friend(friend_id):
    user_id = session.get('user_id')  # Ensure the user is logged in
    if not user_id:
        return jsonify({'error': 'Unauthorized access'}), 401

    # Assuming execute_db_query is your utility function for database operations
    query="select friendship_id FROM friends WHERE (user_id_1 = %s AND user_id_2 = %s) OR (user_id_2 = %s AND user_id_1 = %s)"

    params = (user_id, friend_id,user_id,friend_id)
    friendship_id=execute_db_query(query, params,fetch_one=True)
    print(friendship_id)
    query="DElETE from friends where friendship_id=%s"
    params=(friendship_id)
    execute_db_query(query,params)
    return jsonify({'message': 'Friend deleted successfully'})



#Working related for user searched from the search box
@app.route('/user_details/<int:user_id>')
def user_detail(user_id):
    user_detail = get_user_info_exact(user_id)
    user_list=get_user_lists_any_user(user_id)
    request_status=has_sent_friend_request(session['user_id'],user_id)
   
    return render_template('user_detail.html', user=user_detail,user_list=user_list,status=request_status)

def get_user_info(username):
    """
    Fetch user information from the user table based on the username.
    
    Args:
        username (str): The username to search for in the database.

    Returns:
        list: A list of dictionaries containing 'user_id', 'user_name', and 'email', 
              or None if no user is found.
    """
    query = """
    SELECT user_id, username, email 
    FROM users 
    WHERE username ILIKE %s;
    """
    
    # Parameters for ILIKE query, using wildcards for partial matching
    params = (f'%{username}%',)
        
    # Debug: Print the query and parameters
    print(f"User Query: {query}")
    print(f"Params: {params}")
    
    try:
        # Assuming execute_db_query is a utility function for executing database queries
        result = execute_db_query(query, params, fetch_all=True)
        print(result)
        
        if result:
            # Structure each tuple as a dictionary and return as a list
            users = [
                {
                    'user_id': row[0],   # user_id is at index 0
                    'user_name': row[1], # username is at index 1
                    'email': row[2]      # email is at index 2
                }
                for row in result
            ]
            return users
        else:
            return None  # No user found matching the query
    except Exception as e:
        print(f"Error fetching user info: {e}")
        return None

def has_sent_friend_request(current_user_id, target_user_id):
    """
    Check if the current user has sent a friend request to another user.
    
    Args:
        current_user_id (int): The ID of the logged-in user.
        target_user_id (int): The ID of the user to check against.
    
    Returns:
        bool: True if a pending friend request exists, otherwise False.
    """
    # SQL query to check for a pending friend request
    check_request_query = '''
        SELECT request_id 
        FROM friendship_requests 
        WHERE requester_id = %s AND requestee_id = %s AND status = 'pending'
    '''
    result = execute_db_query(check_request_query, (current_user_id, target_user_id), fetch_one=True)
    
    return result is not None

@app.route('/send_friend_request', methods=['POST'])
def send_friend_request():
    data = request.get_json()
    requester_id = data.get('requester_id')
    requestee_id = data.get('requestee_id')

    # Validate input data
    if not requester_id or not requestee_id:
        return jsonify({"error": "Both requester_id and requestee_id are required."}), 400

    # Insert friend request into the database
    try:
        insert_query = '''
            INSERT INTO friendship_requests(requester_id, requestee_id, status)
            VALUES (%s, %s, %s)
        '''
        execute_db_query(insert_query, (requester_id, requestee_id, 'pending'))
        return jsonify({"message": "Friend request sent successfully!"}), 200
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": "Failed to send friend request."}), 500
 
@app.route('/delete_friend_request2/<int:user_id>',methods=['POST']) 
def delete_friend_request_by_users(user_id):
    """
    Delete a friend request from the friendship_requests table using requester and requestee IDs.

    Args:
        requester_id (int): The ID of the user who sent the friend request.
        requestee_id (int): The ID of the user who received the friend request.

    Returns:
        dict: A dictionary indicating success or failure with a message.
    """
    # Query to delete the friend request
    delete_request_query = '''
        DELETE FROM friendship_requests 
        WHERE requester_id = %s AND requestee_id = %s AND status = 'pending'
    '''
    try:
        # Execute the query
        rows_affected = execute_db_query(delete_request_query, (session['user_id'], user_id))
        
        if rows_affected > 0:
            return {"success": True, "message": "Friend request deleted successfully!"}
        else:
            return {"success": False, "message": "No pending friend request found for the given users."}
    except Exception as e:
        print(f"Error deleting friend request: {e}")
        return {"success": False, "message": "An error occurred while deleting the friend request."}
  


#Working Related To Reviews
@app.route('/api/reviews', methods=['POST'])
def add_review():
    try:
        
        # Retrieve and log request data
        data = request.get_json()
        print("Received data:", data)  # Debugging output
        rating = data.get('rating')
        movie_id = data.get('movie_id', None)
        tv_id = data.get('tv_id', None)
        review_text = data.get('review_text', None)

        if not session['logged_in']:
            return jsonify({"Brother asked a very good question. But brother needs to logged in"}), 400
        # Validate rating
        try:
            rating = int(rating)
        except ValueError:
            return jsonify({"error": "Invalid rating format, must be an integer"}), 400

        if rating < 1 or rating > 5:
            return jsonify({"error": "Rating must be between 1 and 5."}), 400

        # Validate movie_id and tv_id exclusivity
        if (movie_id and tv_id) or (not movie_id and not tv_id):
            return jsonify({"error": "Provide either movie_id or tv_id, but not both or none."}), 400

        # Convert movie_id to integer if it's a string
        try:
            movie_id = int(movie_id) if movie_id else None
        except ValueError:
            return jsonify({"error": "Invalid movie_id format"}), 400

        # Prepare and execute the query
        query = '''INSERT INTO reviews (user_id, movie_id, tv_id, rating, review_text) 
                   VALUES (%s, %s, %s, %s, %s)'''
        
        # Execute query with error handling
        if not execute_db_query(query=query, params=(session['user_id'], movie_id, tv_id, rating, review_text)):
            return jsonify({"error": "Database insertion failed"}), 500

        return jsonify({"message": "Review added successfully"}), 201

    except Exception as e:
        print("An error occurred:", e)
        traceback.print_exc()  # Log the complete stack trace
        return jsonify({"error": "An unexpected error occurred: " + str(e)}), 500

@app.route('/api/reviews/movie/<int:movie_id>', methods=['GET'])
def get_reviews_by_movie(movie_id):
 
    movie_id = int(movie_id) if movie_id else None
    # Define the query to retrieve reviews by movie_id
    query = '''SELECT review_id, user_id, rating, review_text, 
                      allow_interaction, netvotes, created_at, updated_at 
               FROM reviews 
               WHERE movie_id = %s'''

    # Execute the query and fetch reviews
    reviews = execute_db_query(query, (movie_id,), fetch_all=True)

    if reviews is None or len(reviews) == 0:
        return jsonify({"error": "No reviews found for this movie."}), 404

    # Construct the response with the list of reviews
    reviews_list = []
    for review in reviews:
        reviews_list.append({
            "review_id": review[0],
            "user_id": review[1],
            "rating": review[2],
            "review_text": review[3],
            "allow_interaction": review[4],
            "netvotes": review[5],
            "created_at": review[6].isoformat() if review[6] else None,
            "updated_at": review[7].isoformat() if review[7] else None,
        })

    return jsonify({
        "movie_id": movie_id,
        "reviews": reviews_list
    }), 200

@app.route('/api/reviews/<int:review_id>', methods=['DELETE'])
def delete_review(review_id):
    user_id = session.get('user_id')

    # Check if the review exists and if the user is authorized
    query = "SELECT user_id FROM reviews WHERE review_id = %s"
    review = execute_db_query(query, (review_id,), fetch_one=True)
    
    if not review:
        return jsonify({"error": "Review not found"}), 404

    if review[0] != user_id:
        return jsonify({"error": "Unauthorized"}), 403

    # Delete the review
    delete_query = "DELETE FROM reviews WHERE review_id = %s"
    execute_db_query(delete_query, (review_id,))

    return jsonify({"message": "Review deleted successfully"}), 200

@app.route('/api/reviews/<int:review_id>/vote', methods=['POST'])
def vote_review(review_id):
    data = request.get_json()
    user_id = data.get('user_id')
    vote_type = data.get('vote_type')  # True for upvote, False for downvote

    # Validate input
    if not user_id or vote_type is None:
        return jsonify({"error": "user_id and vote_type are required"}), 400

    # Check if the review exists and has text
    review_query = '''SELECT review_text FROM reviews WHERE review_id = %s'''
    review = execute_db_query(review_query, (review_id,), fetch_one=True)

    if not review or not review[0]:
        return jsonify({"error": "Cannot vote on a review without text."}), 400

    # Check for an existing vote by the user on this review
    existing_vote_query = '''SELECT vote_type FROM review_votes WHERE user_id = %s AND review_id = %s'''
    existing_vote = execute_db_query(existing_vote_query, (user_id, review_id), fetch_one=True)

    if existing_vote:
        if existing_vote[0] == vote_type:
            # If the user has already voted the same way, prevent the vote
            return jsonify({"error": "You have already voted this way on this review."}), 400
        else:
            # Update the vote if the user changes their vote
            update_vote_query = '''UPDATE review_votes SET vote_type = %s WHERE user_id = %s AND review_id = %s'''
            execute_db_query(update_vote_query, (vote_type, user_id, review_id))
    else:
        # Insert a new vote
        insert_vote_query = '''INSERT INTO review_votes (user_id, review_id, vote_type) VALUES (%s, %s, %s)'''
        execute_db_query(insert_vote_query, (user_id, review_id, vote_type))

    # Fetch the updated net vote count
    net_votes_query = '''SELECT COALESCE(SUM(CASE WHEN vote_type THEN 1 ELSE -1 END), 0) AS net_votes 
                         FROM review_votes WHERE review_id = %s'''
    net_votes = execute_db_query(net_votes_query, (review_id,), fetch_one=True)

    return jsonify({"message": "Vote registered successfully", "net_votes": net_votes[0]}), 200


@app.route('/api/reviews/<int:review_id>', methods=['PATCH'])
def update_review(review_id):
    """
    Updates the text or rating of a review.

    This function allows the client to update either the review text or the rating 
    of a specified review identified by review_id.

    Expected JSON format for the request body:
    {
        "user_id": <int>,          # ID of the user updating the review (required)
        "new_text": <str>,         # New review text (optional)
        "new_rating": <int>        # New rating (required, must be between 1 and 5)
    }

    Returns:
        - A JSON response with a success message and HTTP status code 200 if the 
          update is successful.
        - A JSON response with an error message and HTTP status code 400 if validation 
          fails (e.g., user_id is required).
        - A JSON response with an error message and HTTP status code 500 if there is 
          a failure during the database update.
    """
    data = request.get_json()

    # Validate required fields
    user_id = data.get('user_id')
    new_text = data.get('new_text')
    new_rating = data.get('new_rating')

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400
    if new_rating is None:  # Rating is mandatory
        return jsonify({"error": "new_rating is required"}), 400

    # Update the review text if provided
    if new_text:
        query = '''UPDATE reviews SET review_text = %s WHERE review_id = %s'''
        execute_db_query(query=query, params=(new_text, review_id))

    # Update the rating
    query = '''UPDATE reviews SET rating = %s WHERE review_id = %s'''
    execute_db_query(query=query, params=(new_rating, review_id))

    return jsonify({"message": "Review updated successfully"}), 200



#Working Related To Comment
# Route to display the comments page
@app.route('/comments_page/<int:review_id>', methods=['GET'])
def comments_page(review_id):
    # Fetch review information
    review_info = execute_db_query(query="SELECT * FROM reviews WHERE review_id=%s", params=(review_id,), fetch_one=True)
    p_review = {
        "user_id": review_info[1],
        "rating": review_info[4],
        "review_text": review_info[5]
    } if review_info else None

    # Fetch comments related to the review_id
    comments = execute_db_query(query="SELECT * FROM comments WHERE review_id = %s", params=(review_id,), fetch_all=True)
    comment_list = []
    if comments:
        for comment in comments:
            comment_list.append({
                "comment_id": comment[0],
                "review_id": comment[1],
                "user_id": comment[2],
                "comment_text": comment[3],
                "created_at": comment[5],
                "votes":comment[4]
            })
     
    # Render the template with review and comments
    return render_template('comments_page.html', review_id=review_id, comments=comment_list, p_review=p_review)

@app.route('/add_comment', methods=['POST'])
def add_comment():
    data = request.get_json()
    user_id = session['user_id']
    review_id = data.get('review_id')
    comment_text = data.get('comment_text')

    if not user_id or not review_id or not comment_text:
        return jsonify({"error": "user_id, review_id, and comment_text are required"}), 400

    query = '''INSERT INTO comments (user_id, review_id, comment_text) VALUES (%s, %s, %s)'''
    execute_db_query(query=query, params=(user_id, review_id, comment_text))

    return jsonify({"message": "Comment added successfully"}), 201

@app.route('/api/comments/<int:comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    data = request.get_json()
    user_id = data.get('user_id')
    print(data)
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    # Check if the comment exists
    query = '''SELECT user_id FROM comments WHERE comment_id = %s'''
    comment = execute_db_query(query=query, params=(comment_id,), fetch_one=True)

    if not comment:
        return jsonify({"error": "Comment not found."}), 404

    # Check if the user is the owner of the comment
    if comment[0] != user_id:
        return jsonify({"error": "You are not authorized to delete this comment."}), 403

    # Proceed with deletion if authorized
    delete_query = '''DELETE FROM comments WHERE comment_id = %s'''
    execute_db_query(query=delete_query, params=(comment_id,))

    return jsonify({"message": "Comment deleted successfully"}), 200

@app.route('/api/comments/<int:comment_id>', methods=['PATCH'])
def update_comment(comment_id):
 
    data = request.get_json()
    user_id = data.get('user_id')
    new_text = data.get('new_text')

    if not user_id or not new_text:
        return jsonify({"error": "user_id and new_text are required"}), 400

    query = '''SELECT user_id FROM comments WHERE comment_id = %s'''
    comment = execute_db_query(query=query, params=(comment_id,), fetch_one=True)

    if not comment:
        return jsonify({"error": "Comment not found."}), 404

    if comment[0] != user_id:
        return jsonify({"error": "You are not authorized to update this comment."}), 403

    update_query = '''UPDATE comments SET comment_text = %s WHERE comment_id = %s'''
    execute_db_query(query=update_query, params=(new_text, comment_id))

    return jsonify({"message": "Comment updated successfully"}), 200

@app.route('/api/comments/<int:comment_id>/vote', methods=['POST'])
def vote_comment(comment_id):
    data = request.get_json()
    user_id = data.get('user_id')
    vote_type = data.get('vote_type')  # This could be "up" or "down"

    # Convert vote_type to boolean
    if vote_type == "up":
        vote_type = True
    elif vote_type == "down":
        vote_type = False
    
    # Validate required fields
    if not user_id or vote_type is None:
        return jsonify({"error": "user_id and vote_type are required"}), 400

    # Check if the user has already voted
    existing_vote_query = '''SELECT vote_type FROM comment_votes WHERE user_id = %s AND comment_id = %s'''
    existing_vote = execute_db_query(existing_vote_query, (user_id, comment_id), fetch_one=True)

    if existing_vote:
        existing_vote_type = existing_vote[0]
        # If the user has already voted differently, update the vote
        if existing_vote_type != vote_type:
            update_vote_query = '''UPDATE comment_votes SET vote_type = %s WHERE user_id = %s AND comment_id = %s'''
            execute_db_query(update_vote_query, (vote_type, user_id, comment_id))
        else:
            return jsonify({"error": "You have already voted this way on this comment."}), 400
    else:
        # If no existing vote, insert the new vote
        insert_vote_query = '''INSERT INTO comment_votes (user_id, comment_id, vote_type) VALUES (%s, %s, %s)'''
        execute_db_query(insert_vote_query, (user_id, comment_id, vote_type))

    return jsonify({"message": "Vote registered successfully"}), 200




#Working Related To list
# Route to display the list page
@app.route('/lists')
def lists():
    # Call get_user_lists function to get the list data
    lists_data = get_user_listsss()

    # If the data retrieval function returns an error (e.g., unauthorized), handle it
    if isinstance(lists_data, tuple) and lists_data[1] == 401:
        return "Unauthorized", 401

    # Pass the list data to the template
    return render_template('lists.html', lists=lists_data)

@app.route('/create_list', methods=['POST'])
def add_list():
    """
    Adds a new list to the database for the given user.

    Parameters:
    - `user_id` (int): ID of the user creating the list.
    - `list_title` (str): Title of the list.
    - `description` (str, optional): Description of the list.
    - `list_type` (str): Type of list ('public', 'private', 'friends_only', or 'watchlist').

    Returns:
    - JSON response indicating success or failure of list creation.
    """
    data = request.get_json()  # Get the JSON data sent from the frontend

    # Extract values from the incoming request
    user_id = session['user_id']
    list_title = data.get('listName')  # 'listName' from JavaScript form
    description = data.get('description')  # Description field from JavaScript form
    list_type = data.get('listType')  # 'listType' from JavaScript form

    # Validate required parameters
    if not user_id or not list_title or not list_type:
        return jsonify({"error": "user_id, list_title, and list_type are required"}), 400

    # SQL query to insert the new list into the database
    query = '''INSERT INTO lists (user_id, list_title, description, list_type)
               VALUES (%s, %s, %s, %s)'''
    
    # Execute the query
    if not execute_db_query(query=query, params=(user_id, list_title, description, list_type)):
        return jsonify({"error": "Failed to create list"}), 500

    return jsonify({"message": "List created successfully"}), 201

@app.route('/api/list_items', methods=['POST'])
def add_item_to_list():
    data = request.get_json()
    list_id = data.get('list_id')
    movie_id = data.get('movie_id', None)
    tv_id = data.get('tv_id', None)

    if not list_id or (not movie_id and not tv_id):
        return jsonify({"error": "Missing required parameters"}), 400

    query = """
    INSERT INTO list_items (list_id, movie_id, tv_id) 
    VALUES (%s, %s, %s) 
    """
    params = (list_id, movie_id, tv_id)
    
    print("Executing query with params:", params)  # Debugging log
    result = execute_db_query(query=query, params=params)

    if result is None:
        print("Insert failed: result is None")  # Debugging log
        return jsonify({"error": "Failed to add item to list"}), 500

    print("Insert successful")  # Debugging log
    return jsonify({"message": "Item added to list successfully"}),201

@app.route('/api/user_lists', methods=['GET'])
def get_user_lists():
    user_id=session['user_id']
    # Query to fetch user lists
    query = "SELECT list_id, list_title FROM lists WHERE user_id = %s"
    params = (user_id,)
    result = execute_db_query(query=query, params=params, fetch_all=True)
    
    # Format the result as a list of dictionaries
    formatted_result = [{"list_id": row[0], "list_title": row[1]} for row in result]

    return jsonify({"lists": formatted_result})


    return jsonify({"lists": result})

@app.route('/api/list_items/list/<int:list_id>', methods=['GET'])
@app.route('/api/list_items/list/<int:list_id>/type', methods=['GET'])
def get_list_items(list_id):
    """
    Retrieves detailed movie information for all movies in a specified list.
    """
    item_type = request.args.get('item_type')  # Optional: Filter by 'movie' or 'tv'
    valid_types = ['movie', 'tv']
    
    if item_type:
        item_types = item_type.split(',')
        if not all(t in valid_types for t in item_types):
            return jsonify({"error": "Invalid item type. Must be 'movie' or 'tv'"}), 400

        columns = [f"{t}_id IS NOT NULL" for t in item_types]
        where_clause = " OR ".join(columns)
        query = f"""
        SELECT * FROM list_items WHERE list_id = %s AND ({where_clause})
        """
    else:
        query = "SELECT * FROM list_items WHERE list_id = %s"

    params = (list_id,)
    list_items = execute_db_query(query=query, params=params, fetch_all=True)

    if not list_items:
        return jsonify({"error": "No items found in the list"}), 404

    list_item=[]
    
    for list in list_items:
        list_item.append({
            "list_item_id":list[0],
            "movie_id":list[2]
        })
    
    # Fetch detailed movie data for each movie_id
    movie_details = []
    for item in list_item:
        if item['movie_id']:
            details = fetch_movie_details(item['movie_id'])
            if details:  # Add only if details were successfully fetched
                movie_details.append(details)
                
                

    return render_template('list_details.html', movies=movie_details,list=list)

@app.route('/api/lists/<int:list_id>/vote', methods=['POST'])
def vote_on_list(list_id):
    """
    Adds or updates a user's vote on a list.

    Parameters:
    - `list_id` (int): ID of the list to vote on.
    - JSON payload fields:
      - `vote_type` (bool): True for upvote, False for downvote.

    Returns:
    - JSON response indicating success or failure of voting.
    """
    data = request.get_json()
    user_id = session.get('user_id')  # Retrieve user_id from the session
    vote_type = data.get('vote_type')  # True for upvote, False for downvote

    if user_id is None or vote_type is None:
        return jsonify({"error": "user_id and vote_type are required"}), 400

    # Check if the user has already voted on this list
    existing_vote_query = '''SELECT vote_type FROM list_votes WHERE user_id = %s AND list_id = %s'''
    existing_vote = execute_db_query(existing_vote_query, (user_id, list_id), fetch_one=True)

    if existing_vote:
        if existing_vote[0] == vote_type:
            # If the user has already voted the same way, prevent the vote
            return jsonify({"error": "You have already voted this way on this list."}), 400
        else:
            # Update the vote if the user changes their vote
            update_vote_query = '''UPDATE list_votes SET vote_type = %s WHERE user_id = %s AND list_id = %s'''
            execute_db_query(update_vote_query, (vote_type, user_id, list_id))
    else:
        # Insert a new vote
        insert_vote_query = '''INSERT INTO list_votes (user_id, list_id, vote_type) VALUES (%s, %s, %s)'''
        execute_db_query(insert_vote_query, (user_id, list_id, vote_type))

    # Fetch the updated net vote count
    net_votes_query = '''SELECT COALESCE(SUM(CASE WHEN vote_type THEN 1 ELSE -1 END), 0) AS net_votes 
                         FROM list_votes WHERE list_id = %s'''
    net_votes = execute_db_query(net_votes_query, (list_id,), fetch_one=True)

    return jsonify({"message": "Vote recorded successfully", "net_votes": net_votes[0]}), 201

@app.route('/api/lists/<int:list_id>', methods=['DELETE'])
def delete_list(list_id):
    """
    Deletes a list by `list_id` from the database.

    Parameters:
    - `list_id` (int): ID of the list to be deleted.

    Returns:
    - JSON response indicating success or failure of list deletion.
    """
    query = "DELETE FROM lists WHERE list_id = %s"
    if not execute_db_query(query=query, params=(list_id,)):
        return jsonify({"error": "Failed to delete list"}), 500

    return jsonify({"message": "List deleted successfully"}), 200

@app.route('/api/list_items/<int:list_item_id>', methods=['DELETE'])
def remove_item_from_list(list_item_id):
    """
    Removes a movie or TV show from a specified list.

    Parameters:
    - `list_item_id` (int): ID of the list item to be removed.

    Returns:
    - JSON response with success or error message.
    """
    # Delete the list item from the database
    query = "DELETE FROM list_items WHERE list_item_id = %s RETURNING list_item_id"
    result = execute_db_query(query=query, params=(list_item_id,), fetch_one=True)

    if result is None:
        return jsonify({"error": "Item not found in the list"}), 404

    return jsonify({"message": "Item removed from list successfully", "list_item_id": result['list_item_id']}), 200

@app.route('/api/lists/<int:list_id>', methods=['PUT'])
def update_list(list_id):
    data = request.get_json()
    list_name = data.get('listName')
    description = data.get('description')
    list_type = data.get('listType')

    if not (list_name and description and list_type):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        # Update the database
        execute_db_query("""
            UPDATE lists
            SET list_title = %s, description = %s, list_type = %s
            WHERE list_id = %s
        """, (list_name, description, list_type, list_id))

        return jsonify({'message': 'List updated successfully!'}), 200
    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to update the list'}), 500

def get_user_listsss():
    user_id = session.get('user_id')
    if not user_id:
        return []  # Return an empty list if not authenticated

    # Query to fetch user lists
    query = "SELECT list_id, list_title, description, list_type,netvotes FROM lists WHERE user_id = %s"
    params = (user_id,)
    result = execute_db_query(query=query, params=params, fetch_all=True)
    
    # Format the result as a list of dictionaries
    if not result:
        return []  # Return an empty list if no lists found

    formatted_result = [
        {"list_id": row[0], "list_title": row[1], "description": row[2], "list_type": row[3],"netvotes":row[4]} 
        for row in result
    ]

    return formatted_result



#Working related to recommendation 
def recommend_for_user(picked_userid):
    # Load data from database
    def load_data():
        query = """
        SELECT user_id, movie_id, rating
        FROM reviews
        WHERE rating IS NOT NULL
        """
        return execute_db_query(query, fetch_all=True)

    # Aggregate ratings and filter movies with at least 5 reviews
    def aggregate_ratings(df):
        agg_ratings = df.groupby('movie_id').agg(
            mean_rating=('rating', 'mean'),
            number_of_ratings=('rating', 'count')
        ).reset_index()
        return agg_ratings[agg_ratings['number_of_ratings'] >= 5]

    # Create user-item matrix
    def create_user_item_matrix(df_filtered):
        matrix = df_filtered.pivot_table(index='user_id', columns='movie_id', values='rating')
        return matrix

    # Normalize the matrix
    def normalize_matrix(matrix):
        matrix_norm = matrix.subtract(matrix.mean(axis=1), axis='rows')
        matrix_norm.fillna(0, inplace=True)
        return matrix_norm

    # Compute user similarity
    def compute_user_similarity(matrix_norm):
        user_similarity_cosine = cosine_similarity(matrix_norm)
        user_similarity_cosine_df = pd.DataFrame(user_similarity_cosine, index=matrix_norm.index, columns=matrix_norm.index)
        return user_similarity_cosine_df

    # Get similar users with dynamic threshold
    def get_similar_users(user_similarity_cosine_df, picked_userid):
        """
        Fetch similar users for the picked user ID.
        If the user has few or no reviews, compute a dynamic threshold based on overall similarities.
        """
        similarity_scores = user_similarity_cosine_df.loc[picked_userid].drop(index=picked_userid, errors='ignore')
        
        threshold = similarity_scores.nlargest(10).mean() if not similarity_scores.empty else 0.0
        similar_users = similarity_scores[similarity_scores > threshold]

        return similar_users.sort_values(ascending=False)


    # Prepare item pool
    def prepare_item_pool(matrix_norm, picked_userid, similar_users):
        picked_userid_watched = matrix_norm.loc[picked_userid][matrix_norm.loc[picked_userid] > 0]
        similar_user_movies = matrix_norm.loc[similar_users.index]
        similar_user_movies = similar_user_movies.loc[:, (similar_user_movies != 0).any(axis=0)]
        similar_user_movies.drop(columns=picked_userid_watched.index, inplace=True, errors='ignore')
        return similar_user_movies

    # Recommend items
    def recommend_items(similar_user_movies, similar_users):
        item_score = {}
        for i in similar_user_movies.columns:
            movie_rating = similar_user_movies[i]
            score = sum(movie_rating[u] * similar_users[u] for u in similar_users.index if movie_rating[u] != 0)
            count = sum(1 for u in similar_users.index if movie_rating[u] != 0)
            if count > 0:
                item_score[i] = score / count
        ranked_item_score = pd.DataFrame(item_score.items(), columns=['movie_id', 'movie_score']).sort_values(by='movie_score', ascending=False)
        return ranked_item_score

    # Main flow
    data = load_data()
    df = pd.DataFrame(data, columns=['user_id', 'movie_id', 'rating'])

    agg_ratings = aggregate_ratings(df)
    df_filtered = df[df['movie_id'].isin(agg_ratings['movie_id'])]

    matrix = create_user_item_matrix(df_filtered)
    matrix_norm = normalize_matrix(matrix)

    user_similarity_cosine_df = compute_user_similarity(matrix_norm)
    similar_users = get_similar_users(user_similarity_cosine_df, picked_userid)
    similar_user_movies = prepare_item_pool(matrix_norm, picked_userid, similar_users)

    recommendations = recommend_items(similar_user_movies, similar_users)

    recommended_movie_ids = recommendations['movie_id'].tolist()
    return recommended_movie_ids

def get_movie_recommendations(user_id):
    """
    Returns movie recommendations for a specific user.

    Parameters:
        user_id (int): The ID of the user for whom recommendations are generated.

    Returns:
        JSON response containing:
            - user_id (int): The ID of the user.
            - recommended_movies (list): A list of recommended movie IDs.
    """
    # Check if the user has rated at least one movie
    query = """
    SELECT COUNT(*) 
    FROM reviews 
    WHERE user_id = %s AND rating IS NOT NULL
    """
    user_review_count = execute_db_query(query, (user_id,), fetch_one=True)

    if user_review_count and user_review_count[0] > 0:
        # User has rated at least one movie, proceed with recommendations
        recommended_movie_ids = recommend_for_user(user_id)
        
        if recommended_movie_ids:
            return jsonify({
                "user_id": user_id,
                "recommended_movies": recommended_movie_ids
            }), 200
        else:
            return jsonify({
                "error": "No recommendations available at the moment."
            }), 404
    else:
        # User has not rated any movies
        return jsonify({
            "error": "User has not rated any movies yet."
        }), 400



if __name__ == '__main__':
    app.run(debug=True)
    


