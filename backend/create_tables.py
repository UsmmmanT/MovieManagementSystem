import psycopg2
from db_config import get_db_connection

# Define table creation queries
create_movies_table = """
CREATE TABLE IF NOT EXISTS movies (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    release_date DATE,
    overview TEXT,
    runtime INTEGER,
    budget BIGINT,
    revenue BIGINT,
    genres JSONB,
    average_rating FLOAT,
    vote_count INTEGER,
    backdrop_path VARCHAR(255),
    poster_path VARCHAR(255),
    homepage VARCHAR(255),
    imdb_id VARCHAR(255)
);
"""

create_tv_table = """
CREATE TABLE IF NOT EXISTS tv (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    first_air_date DATE,
    overview TEXT,
    number_of_seasons INTEGER,
    number_of_episodes INTEGER,
    genres JSONB,
    average_rating FLOAT,
    vote_count INTEGER,
    backdrop_path VARCHAR(255),
    poster_path VARCHAR(255),
    homepage VARCHAR(255),
    original_language VARCHAR(10)
);
"""

create_seasons_table = """
CREATE TABLE IF NOT EXISTS seasons (
    id SERIAL PRIMARY KEY,
    tv_show_id INTEGER REFERENCES tv(id),
    season_number INTEGER,
    overview TEXT,
    air_date DATE,
    episode_count INTEGER
);
"""

create_episodes_table = """
CREATE TABLE IF NOT EXISTS episodes (
    id SERIAL PRIMARY KEY,
    season_id INTEGER REFERENCES seasons(id),
    episode_number INTEGER,
    title VARCHAR(255),
    overview TEXT,
    air_date DATE,
    vote_average FLOAT,
    vote_count INTEGER
);
"""

create_people_table = """
CREATE TABLE IF NOT EXISTS people (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    biography TEXT,
    birthday DATE,
    deathday DATE,
    gender VARCHAR(10),
    homepage VARCHAR(255),
    imdb_id VARCHAR(255),
    popularity FLOAT,
    profile_path VARCHAR(255),
    place_of_birth VARCHAR(255),
    also_known_as JSONB
);
"""

create_companies_table = """
CREATE TABLE IF NOT EXISTS companies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    headquarters VARCHAR(255),
    homepage VARCHAR(255),
    logo_path VARCHAR(255),
    origin_country VARCHAR(100),
    parent_company INTEGER REFERENCES companies(id)
);
"""

create_keywords_table = """
CREATE TABLE IF NOT EXISTS keywords (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL
);
"""

create_collections_table = """
CREATE TABLE IF NOT EXISTS collections (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    overview TEXT,
    poster_path VARCHAR(255),
    backdrop_path VARCHAR(255)
);
"""

create_networks_table = """
CREATE TABLE IF NOT EXISTS networks (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    headquarters VARCHAR(255),
    homepage VARCHAR(255),
    logo_path VARCHAR(255),
    origin_country VARCHAR(100)
);
"""

create_genres_table = """
CREATE TABLE IF NOT EXISTS genres (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL
);
"""

create_users_table = """
CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    profile_picture VARCHAR(255),
    bio TEXT,
    preferences JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

create_friendships_table = """
CREATE TABLE IF NOT EXISTS friendships (
    friendship_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id),
    friend_id INTEGER REFERENCES users(user_id),
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

create_user_reviews_table = """
CREATE TABLE IF NOT EXISTS user_reviews (
    review_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id),
    movie_id INTEGER REFERENCES movies(id),
    tv_show_id INTEGER REFERENCES tv(id),
    parent_review_id INTEGER REFERENCES user_reviews(review_id),
    rating INTEGER CHECK (rating >= 1 AND rating <= 10),
    review_text TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

create_user_likes_table = """
CREATE TABLE IF NOT EXISTS user_likes (
    like_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id),
    review_id INTEGER REFERENCES user_reviews(review_id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

create_watchlist_table = """
CREATE TABLE IF NOT EXISTS watchlist (
    watchlist_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id),
    movie_id INTEGER REFERENCES movies(id),
    tv_show_id INTEGER REFERENCES tv(id),
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

create_user_activity_log_table = """
CREATE TABLE IF NOT EXISTS user_activity_log (
    activity_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id),
    activity_type VARCHAR(50),
    target_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

create_notifications_table = """
CREATE TABLE IF NOT EXISTS notifications (
    notification_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id),
    message TEXT,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

create_user_lists_table = """
CREATE TABLE IF NOT EXISTS user_lists (
    list_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

create_list_items_table = """
CREATE TABLE IF NOT EXISTS list_items (
    list_item_id SERIAL PRIMARY KEY,
    list_id INTEGER REFERENCES user_lists(list_id),
    movie_id INTEGER REFERENCES movies(id),
    tv_show_id INTEGER REFERENCES tv(id),
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

# Function to execute the table creation queries
def create_tables():
    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor() as cursor:
                # Execute each table creation query
                cursor.execute(create_movies_table)
                cursor.execute(create_tv_table)
                cursor.execute(create_seasons_table)
                cursor.execute(create_episodes_table)
                cursor.execute(create_people_table)
                cursor.execute(create_companies_table)
                cursor.execute(create_keywords_table)
                cursor.execute(create_collections_table)
                cursor.execute(create_networks_table)
                cursor.execute(create_genres_table)
                cursor.execute(create_users_table)
                cursor.execute(create_friendships_table)
                cursor.execute(create_user_reviews_table)
                cursor.execute(create_user_likes_table)
                cursor.execute(create_watchlist_table)
                cursor.execute(create_user_activity_log_table)
                cursor.execute(create_notifications_table)
                cursor.execute(create_user_lists_table)
                cursor.execute(create_list_items_table)

        print("Tables created successfully.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()

# Call the function to create tables
if __name__ == "__main__":
    create_tables()
