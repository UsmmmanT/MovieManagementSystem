import tmdbsimple as tmdb
from db_config import get_db_connection
from concurrent.futures import ThreadPoolExecutor, as_completed

tmdb.API_KEY = "4328059314cf1e2d573176490f1c69a3"

def fetch_movie_data(query, page=1):
    """Fetch movie data from TMDB API for a specific page."""
    try:
        search = tmdb.Search()
        response = search.movie(query=query, page=page)
        return response.get('results', [])
    except Exception as e:
        print(f"Error fetching movie data from TMDB: {e}")
        return []

def is_movie_in_db(movie_id, cursor):
    """Check if the movie already exists in the database."""
    query = "SELECT COUNT(*) FROM Movies WHERE id = %s"
    cursor.execute(query, (movie_id,))
    count = cursor.fetchone()[0]
    return count > 0

def insert_movie(movie, cursor, conn):
    """Insert movie data into the database using an existing cursor and connection."""
    data = (
        movie.get('id'),
        movie.get('title'),
        movie.get('release_date') or None,
        movie.get('overview'),
        movie.get('adult', False),
        movie.get('genre_ids'),
        movie.get('original_language'),
        movie.get('original_title'),
        movie.get('popularity'),
        movie.get('video', False),
        movie.get('vote_average'),
        movie.get('vote_count'),
        movie.get('backdrop_path'),
        movie.get('poster_path')
    )

    try:
        insert_query = """
        INSERT INTO Movies (id, title, release_date, overview, adult, genre_ids, original_language, 
                            original_title, popularity, video, vote_average, vote_count, 
                            backdrop_path, poster_path)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, data)
        conn.commit()
        return True  # Indicate success
    except Exception as e:
        print(f"Error inserting movie '{movie.get('title')}' into database: {e}")
        return False  # Indicate failure

def process_movie(movie):
    """Process the movie by checking if it's in the database and inserting if not."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if not is_movie_in_db(movie.get('id'), cursor):
            if insert_movie(movie, cursor, conn):
                return f"Success: Inserted movie '{movie['title']}'."
            else:
                return f"Failure: Could not insert movie '{movie['title']}'."
        else:
            return f"Failure: Movie '{movie['title']}' already exists in the database."
    finally:
        cursor.close()
        conn.close()

def retrieve_movies(query, num_pages=1):
    """Main function to fetch and insert movie data."""
    all_movies = []

    # Fetch movie data in parallel
    with ThreadPoolExecutor() as executor:
        fetch_futures = [executor.submit(fetch_movie_data, query, page) for page in range(1, num_pages + 1)]

        # Collect all movies from the completed futures
        for future in as_completed(fetch_futures):
            all_movies.extend(future.result())

    # Process each movie in parallel
    if all_movies:
        with ThreadPoolExecutor() as executor:
            process_futures = [executor.submit(process_movie, movie) for movie in all_movies]
            for future in as_completed(process_futures):
                print(future.result())
    else:
        print("Failure: No movies found.")

if __name__ == "__main__":
    query_string = "hero"  # Query string to search for movies
    num_pages = 6            # Number of pages to fetch from the API
    retrieve_movies(query_string, num_pages)
