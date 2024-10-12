import tmdbsimple as tmdb
from db_config import get_db_connection

tmdb.API_KEY = "4328059314cf1e2d573176490f1c69a3"

def fetch_movie_data(query, page=1):
    """Fetch movie data from TMDB API."""
    try:
        search = tmdb.Search()
        response = search.movie(query=query, page=page)
        return response.get('results', [])
    except Exception as e:
        print(f"Error fetching movie data: {e}")
        return []

def is_movie_in_db(movie_id, cursor):
    """Check if the movie already exists in the database."""
    query = "SELECT COUNT(*) FROM Movies WHERE id = %s"
    cursor.execute(query, (movie_id,))
    count = cursor.fetchone()[0]
    return count > 0

def insert_movie(movie):
    """Insert movie data into the database."""
    # Prepare the data, ensuring that empty fields are handled correctly
    data = (
        movie.get('id'),                   # id
        movie.get('title'),                # title
        movie.get('release_date') or None,  # release_date (set to None if not present)
        movie.get('overview'),              # overview
        movie.get('adult', False),         # adult (default to False if not present)
        movie.get('genre_ids'),            # genre_ids
        movie.get('original_language'),     # original_language
        movie.get('original_title'),        # original_title
        movie.get('popularity'),            # popularity
        movie.get('video', False),         # video (default to False if not present)
        movie.get('vote_average'),          # vote_average
        movie.get('vote_count'),            # vote_count
        movie.get('backdrop_path'),         # backdrop_path
        movie.get('poster_path')            # poster_path
    )

    try:
        # Inserting the record into the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # SQL query to insert the record
        insert_query = """
        INSERT INTO Movies (id, title, release_date, overview, adult, genre_ids, original_language, 
                            original_title, popularity, video, vote_average, vote_count, 
                            backdrop_path, poster_path)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        cursor.execute(insert_query, data)  # Execute the insertion with the data tuple
        conn.commit()  # Commit the changes to the database

        # Clean up
        cursor.close()
        conn.close()
        return True  # Indicate success
    except Exception as e:
        print(f"Error inserting movie '{movie.get('title')}' into database: {e}")
        return False  # Indicate failure

def main():
    """Main function to fetch and insert movie data."""
    query = "The Irishman"
    movies = fetch_movie_data(query)

    if movies:  # Check if there are any results
        conn = get_db_connection()
        cursor = conn.cursor()
        
        for movie in movies:  # Loop through all movies
            if not is_movie_in_db(movie.get('id'), cursor):
                if insert_movie(movie):
                    print(f"Success: Inserted movie '{movie['title']}'.")
                else:
                    print(f"Failure: Could not insert movie '{movie['title']}'.")
            else:
                print(f"Failure: Movie '{movie['title']}' already exists in the database.")

        cursor.close()
        conn.close()
    else:
        print("Failure: No movies found.")

if __name__ == "__main__":
    main()
