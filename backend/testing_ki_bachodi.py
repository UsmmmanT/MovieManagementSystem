import tmdbsimple as tmdb

# Set your TMDB API key
tmdb.API_KEY = '4328059314cf1e2d573176490f1c69a3'

def get_class_info_keys():
    # Using known values for IDs to ensure valid results
    movie = tmdb.Movies(550)  # ID for the movie "Fight Club"
    tv = tmdb.TV(1399)  # ID for the TV show "Game of Thrones"
    person = tmdb.People(287)  # ID for actor "Brad Pitt"
    company = tmdb.Companies(1)  # ID for "Lucasfilm"
    keyword = tmdb.Keywords(3417)  # ID for the keyword "space"
    collection = tmdb.Collections(10)  # ID for "Star Wars Collection"
    network = tmdb.Networks(213)  # ID for "Netflix"
    #review = tmdb.Reviews('58b5a42dc3a368411800018a')  # Known review ID

    data = {
        "Movies Info Keys": list(movie.info().keys()),
        "TV Info Keys": list(tv.info().keys()),
        "People Info Keys": list(person.info().keys()),
        "Company Info Keys": list(company.info().keys()),
        "Keyword Info Keys": list(keyword.info().keys()),
        "Collection Info Keys": list(collection.info().keys()),
        "Network Info Keys": list(network.info().keys())
    }

    return data

# Retrieve and print the data keys
info_keys = get_class_info_keys()
for key, value in info_keys.items():
    print(f"{key}: {value}")
