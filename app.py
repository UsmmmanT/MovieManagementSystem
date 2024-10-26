import tmdbsimple as tmdb
from flask import Flask, render_template, request

tmdb.API_KEY = "4328059314cf1e2d573176490f1c69a3"  # Your TMDB API key

app = Flask(__name__)

# Clear the template cache
@app.before_request
def clear_template_cache():
    app.jinja_env.cache = {}
    
def fetch_movie_details(movie_id):
    """Fetch detailed movie data from TMDB API."""
    try:
        movie = tmdb.Movies(movie_id)
        details = movie.info()
        return {
            "title": details.get("title"),
            "release_year": details.get("release_date", "").split("-")[0],
            "poster_url": f"https://image.tmdb.org/t/p/w500{details.get('poster_path')}" if details.get('poster_path') else "",
            "popularity": details.get("popularity"),
            "genres": [genre.get("name") for genre in details.get("genres", [])],
            "overview": details.get("overview"),
        }
    except Exception as e:
        print(f"Error fetching movie details: {e}")
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


def popular():
    """Fetches popular movies from TMDB API."""
    try:
        movies_t = tmdb.Movies(671)
        popular_movies = movies_t.popular()
        movies = popular_movies.get('results', [])
        filtered_movies = [
            {
                "title": movie.get("title"),
                "release_date": movie.get("release_date", "").split("-")[0],
                "backdrop_url": f"https://image.tmdb.org/t/p/w500{movie.get('backdrop_path')}" if movie.get('backdrop_path') else "",
                "poster_url": f"https://image.tmdb.org/t/p/w500{movie.get('poster_path')}" if movie.get('poster_path') else "",
            }
            for movie in movies
        ]
        return filtered_movies
    except Exception as e:
        print(f"Error fetching popular movies: {e}")
        return []

# Route for Home Page
@app.route('/')
def index():
    # Get the list of popular movies
    movies_list = popular()
    
    # Pass the filtered movie data to index.html
    return render_template('index.html', movies=movies_list)

# Route for Sign In Page
@app.route('/signin')
def signin():
    return render_template('signin.html')

# Route for Search Page
@app.route('/search', methods=['GET', 'POST'])
def search():  
    return render_template('search.html')

# Route for Sign-up Page
@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/movies')
def movies():
    query = request.args.get('movie')
    if query:
        movie_data = fetch_movie_data(query)
        return render_template('movies.html', movies=movie_data)
    else:
        return render_template('movies.html', movies=[])

@app.route('/movie/<int:movie_id>')
def movie_detail(movie_id):
    movie_info = fetch_movie_details(movie_id)
    return render_template('movie_detail.html', movie=movie_info)


if __name__ == '__main__':
    app.run(debug=True)
