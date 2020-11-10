package auth_test

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/smhanov/auth"
)

// Create our own database, and
// override the GetSamlIdentityProviderForUser method
type myDB struct{ auth.DB }
type myTx struct{ auth.Tx }

func (db myDB) Begin(ctx context.Context) auth.Tx {
	return myTx{db.DB.Begin(ctx)}
}

func (tx myTx) GetSamlIdentityProviderForUser(email string) string {
	if email == "user@example.com" {
		return ""
	}
	return tx.GetSamlIdentityProviderByID("https://samltest.id/saml/idp")
}

func serveMainPage(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(mainWebPage))
}

// Example_saml shows how to register Saml providers and
// override the GetSamlIdentityProviderForUser method
func Example_saml() {

	// Open the database
	rawdb, err := sqlx.Open("sqlite3", "mydatabase.db")
	if err != nil {
		log.Panic(err)
	}

	db := myDB{auth.NewUserDB(rawdb)}

	// Download IDP metadata and register it. This only needs to be done once, not
	// every time the program starts. But for simplicity, we do it here.
	xml := fetchURL("https://samltest.id/saml/idp")

	tx := db.Begin(context.Background())
	tx.AddSamlIdentityProviderMetadata(auth.GetSamlID(xml), xml)
	if tx.GetUserByEmail("user@example.com") == 0 {
		tx.CreatePasswordUser("user@example.com", auth.HashPassword("password"))
	}
	tx.Commit()

	// Register the handler.
	http.Handle("/user/", auth.New(db, auth.DefaultSettings))
	http.HandleFunc("/", serveMainPage)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Fetch the URL and return its contents as a string
func fetchURL(url string) string {
	resp, err := http.Get("https://samltest.id/saml/idp")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	buf := new(strings.Builder)
	io.Copy(buf, resp.Body)
	return buf.String()
}

const mainWebPage = `<!DOCTYPE html>
<html>
    <body>
        <div>
            To run this, 
            <ol>
            <li>Download <a href="/user/saml/metadata">the Service Provider Metadata</a> and
                send it to <a href="https://samltest.id/upload.php">https://samltest.id/upload.php</a>
            </ol>
        </div>
        <div class="wait">Please wait...</div>
        <div class="not-signed-in">
            <h1>You need to sign in.</h1>
            <div>Please sign in as user@example.com with password "password", or enter any other email
            to use single sign in.</div>
            Email: <input type="text" id="email"><br>
            Password: <input type="text" id="password"><br>
            <button onclick="signin(false)">Sign in</button>
            <button onclick="signin(true)">Start Single Sign-On</button>
        </div>
        <div class="signed-in">
            <h1>Hello, <span class="username"></span></h1>
            <pre class="info"></pre>
            <button onclick="signout()">Sign out</button>
        </div>
        <script>
        
async function main() {
    // hide everything until we know if we are signed in.
    show(".not-signed-in", false);
    show(".signed-in", false);

    // get the user information
    let response = await fetch("/user/get");
    show(".wait", false);

    if (response.status === 401) {
        // We are not logged in.
        show(".not-signed-in", true);
        return;
    }
    onsignedin(await response.json());
}

async function onsignedin(json) {
    show(".signed-in", true);
    show(".not-signed-in", false);
    document.querySelector(".username").textContent = json.email;
    document.querySelector(".info").textContent = JSON.stringify(json, null, 4);
}

async function signin(sso) {
    let email = document.querySelector("#email").value;
    let password = document.querySelector("#password").value;
    if (!sso) {
        let response = await fetch("/user/auth?email="+encodeURIComponent(email) + "&password="+encodeURIComponent(password));
        if (response.status === 200) {
            onsignedin(await response.json());
            return;
        } else if (response.status !== 407) {
            alert("Error signing in: " + response.status);
        }
    }

    // for SSO signin, reload the web page
    location.href = "/user/auth?sso=1&email="+encodeURIComponent(email);
}

async function signout() {
    await fetch("/user/signout");
    location.reload();
}

function show(selector, show) {
    document.querySelector(selector).style.display = show ? "" : "none";
}

main();

        </script>
    </body>
</html>`
