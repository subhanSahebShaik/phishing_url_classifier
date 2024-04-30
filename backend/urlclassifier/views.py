from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
import requests
from django.http import JsonResponse
from urllib.parse import urlparse
import datetime
import whois
from .settings import BASE_DIR
import os
import pickle
from bs4 import BeautifulSoup


HTML_CONTENT = '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Phishing URL Detection</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400..900;1,400..900&display=swap" rel="stylesheet">
  <!-- Bootstrap CSS -->
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
  <!-- Custom CSS -->
  <style>
    body, html {
      height: 100%;
      margin: 0;
      font-family: "Playfair Display", serif;
    }
    .container-fluid {
      height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      background-color: #f0f0f0; /* Light grey background */
    }
    .content {
      text-align: center;
    }
    .message {
      font-size: 20px;
      background-image: linear-gradient(to right, red, blue);
      /* Ensure text is visible */
      -webkit-background-clip: text;
      background-clip: text;
      color: transparent;
    }
  </style>
</head>
<body>
  <div class="container-fluid">
    <div class="content">
      <div class="message">This URL is not intended for direct usage. It should only be accessed as an API.</div>
    </div>
  </div>
</body>
</html>
'''


def get_dot_count(url):
    return url.count('.')


def get_url_length(url):
    return len(url)


def get_digit_count(url):
    return sum(c.isdigit() for c in url)


def get_special_char_count(url):
    count = 0
    special_characters = [';', '+=', '_', '?', '=', '&', '[', ']']
    for each_letter in url:
        if each_letter in special_characters:
            count = count + 1
    return count


def get_hyphen_count(url):
    return url.count('-')


def get_double_slash(url):
    return url.count('//')


def get_single_slash(url):
    return url.count('/')


def get_at_the_rate(url):
    return url.count('@')


def get_protocol(url):
    protocol = urlparse(url)
    if (protocol.scheme == 'http'):
        return 1
    else:
        return 0


def get_protocol_count(url):
    http_count = url.count('http')
    https_count = url.count('https')
    # correcting the miscount of https as http
    http_count = http_count - https_count
    return (http_count + https_count)


def perform_whois(url):
    try:
        whois_result = whois.whois(url)
        return whois_result
    except Exception as e:
        return False


def get_registered_date_in_days(whois_result):
    if (whois_result != False):
        created_date = whois_result.creation_date
        if ((created_date is not None) and (type(created_date) != str)):
            if (type(created_date) == list):
                created_date = created_date[0]
            today_date = datetime.datetime.now()
            days = (today_date-created_date).days
            return days
        else:
            return -1
    else:
        return -1


def get_expiration_date_in_days(whois_result):
    if (whois_result != False):
        expiration_date = whois_result.expiration_date
        if ((expiration_date is not None) and (type(expiration_date) != str)):
            if (type(expiration_date) == list):
                expiration_date = expiration_date[0]
            today_date = datetime.datetime.now()
            days = (expiration_date-today_date).days
            return days
        else:
            return -1
    else:
        return -1


def get_updated_date_in_days(whois_result):
    if (whois_result != False):
        updated_date = whois_result.updated_date
        if ((updated_date is not None) and (type(updated_date) != str)):
            if (type(updated_date) == list):
                updated_date = updated_date[0]
            today_date = datetime.datetime.now()
            days = (today_date-updated_date).days
            return days
        else:
            return -1
    else:
        return -1


def get_result(features):
    model_path = os.path.join(BASE_DIR, "Models/random_forest_calssifier.pkl")
    model = pickle.load(open(model_path, "rb"))
    return model.predict([features])


def extract_features(url):
    whois_result = perform_whois(url)
    features = [get_registered_date_in_days(whois_result),
                get_expiration_date_in_days(whois_result),
                get_updated_date_in_days(whois_result),
                get_dot_count(url),
                get_url_length(url),
                get_digit_count(url),
                get_special_char_count(url),
                get_hyphen_count(url),
                get_double_slash(url),
                get_single_slash(url),
                get_at_the_rate(url),
                get_protocol_count(url)
                ]
    return features


def get_data(url):
    try:
        response = requests.get(url, allow_redirects=True)
        text = response.text
        soup = BeautifulSoup(text, "html.parser")
        for script in soup.find_all("script"):
            script.extract()
        for link in soup.find_all("link", {"rel": "preload", "as": "script"}):
            link.extract()
        cleaned_html = str(soup)
    except Exception as e:
        return {"exception": str(e), "prediction": "Since it is erroreneous, there might be a chance that it can be a unsafe."}
    if url.startswith("http://"):
        url = url[7:]
    if url.startswith("https://"):
        url = url[8:]
    features = extract_features(url)
    prediction = get_result(features)[0]
    json_data = {
        "Requested_URL": url,
        "Destinaton_URL": response.url,
        "Registered_Date_in_Days": features[0],
        "Expiration_Date_in_Days": features[1],
        "Updated_Date_in_Days": features[2],
        "Dot_Count": features[3],
        "URL_Length": features[4],
        "Digit_Count": features[5],
        "Special_Char_Count": features[6],
        "Hyphen_Count": features[7],
        "Double_Slash_Count": features[8],
        "Single_Slash_Count": features[9],
        "At_The_Rate_Count": features[10],
        "Protocol_Count": features[11],
        "prediction": "Safe" if prediction == 0 else "Unsafe",
        "JS_removed_HTML": cleaned_html
    }
    return json_data


@csrf_exempt
def index(request):
    if request.method == "POST":
        url = request.POST["URL"]
        json_data = get_data(url)
        return JsonResponse(json_data)
    return HttpResponse(HTML_CONTENT)
