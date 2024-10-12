import requests

url = "https://api.themoviedb.org/3/find/external_id?external_source="

headers = {
    "accept": "application/json",
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiI0MzI4MDU5MzE0Y2YxZTJkNTczMTc2NDkwZjFjNjlhMyIsIm5iZiI6MTcyODY2NjQ5MC42MTEwMTYsInN1YiI6IjY3MDgwMzA1YzkyYzJlNTZkODYxNmVmNCIsInNjb3BlcyI6WyJhcGlfcmVhZCJdLCJ2ZXJzaW9uIjoxfQ.lG0A_hI4wFMJWZxQjE0IPYuXV6iiriWUhM9qE8_bb7I"
}

response = requests.get(url, headers=headers)

print(response.text)