import React, { useState } from "react";
import Stack from "@mui/material/Stack";
import TextField from "@mui/material/TextField";
import Button from "@mui/material/Button";
import SendIcon from "@mui/icons-material/Send";
import CircularProgress from "@mui/material/CircularProgress";
import axios from "axios";
import "./App.css"; // Import CSS file

function Footer({ name }) {
  return (
    <footer className="footer">
      Designed & Developed by {name} (2&#x2764;&#xfe0f;24) Sri Vasavi Engg.
      College
    </footer>
  );
}

function App() {
  const [responseData, setResponseData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [background, setBackground] = useState("#f8f9fa");
  const [error, setError] = useState(null);

  const handleFormSubmit = () => {
    const url = document.querySelector("#standard-basic").value;
    const form_data = new FormData();
    form_data.append("URL", url);

    setLoading(true);

    axios
      .post("https://phishing-url-classifier.onrender.com/", form_data)
      .then((response) => {
        if (response.data.exception) {
          setError(response.data.exception);
          setBackground("#fff0f0");
        } else {
          setResponseData(response.data);
          setBackground(
            response.data.prediction === "Safe" ? "#e0ffe0" : "#fff0f0"
          );
        }
      })
      .catch((error) => {
        console.error(error);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  return (
    <div className="container-fluid" style={{ backgroundColor: background }}>
      <h1 className="title">PhishDefender</h1>
      <div className="content">
        {loading ? (
          <CircularProgress />
        ) : error ? (
          <p className="error">
            {error}
            <br />
            <b>It might be a unsafe one!..</b>
          </p>
        ) : responseData ? (
          <div
            style={{
              width: "100%",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-evenly",
            }}
          >
            <div>
              <p>Requested URL: {responseData.Requested_URL}</p>
              <p>Destination URL: {responseData.Destinaton_URL}</p>
              <p>
                <b>It seems {responseData.prediction}</b>
              </p>
            </div>
            {responseData.JS_removed_HTML && (
              <div className="html-content">
                <p>JS removed version of your requestes URL</p>
                <iframe
                  srcDoc={responseData.JS_removed_HTML}
                  title="Cleaned HTML Content"
                  style={{ width: "100%", height: "400px" }}
                ></iframe>
              </div>
            )}
          </div>
        ) : (
          <React.Fragment>
            <p>
              Think before you click!
              <br />
              We wish you're not going to be a victim...
            </p>
            <Stack direction="row" spacing={2}>
              <TextField
                id="standard-basic"
                label="URL"
                variant="standard"
                style={{ width: "100%" }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    handleFormSubmit();
                  }
                }}
              />
              <Button
                variant="contained"
                endIcon={<SendIcon />}
                style={{ maxHeight: "50%", padding: "0px 20px" }}
                color="primary"
                onClick={handleFormSubmit}
              >
                Submit
              </Button>
            </Stack>
          </React.Fragment>
        )}
        <Footer name={"Subhan Saheb Shaik"} />
      </div>
    </div>
  );
}

export default App;
