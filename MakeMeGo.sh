# Create directories if they do not exist
mkdir -p apis
mkdir -p extras

touch apis/api.go

cat << EOF > apis/api.go
package apis

import (
	"example.com/db"
	"github.com/labstack/echo/v4"
)

type APIBusiness interface {
	Connect(*db.DatabaseConnection) error
	GET(interface{}) (interface{}, error)
	POST(interface{}) (interface{}, error)
	MULTIPOST(interface{}) (interface{}, error)
	PUT(interface{}) (interface{}, error)
	GETBYID(interface{}) (interface{}, error)
	DELETE(interface{}) (interface{}, error)
}

type APIHandler interface {
	Connect(APIBusiness) error
	GET(echo.Context) error
	POST(echo.Context) error
	MULTIPOST(echo.Context) error
	PUT(echo.Context) error
	DELETE(echo.Context) error
	GETBYID(echo.Context) error
}

type APIRouter interface {
	Connect(string, APIHandler, *echo.Echo, AuthHandler) error
}

type AuthBusiness interface {
	Connect(*db.DatabaseConnection) error
	Authenticate(string, string) (error, string, string)
	Authentication(string, string) (interface{}, error)
}

type AuthHandler interface {
	Connect(AuthBusiness) error
	Authentication(echo.Context) error
	Authenticate(func(ec echo.Context) error, ...string) func(ec echo.Context) error
}

type AuthRouter interface {
	Connect(string, AuthHandler, *echo.Echo) error
}
EOF

touch apis/main.go

cat << EOF > apis/main.go
package apis

import (
	"example.com/db"
	"github.com/labstack/echo/v4"
)

type API struct {
	ApiHandler  APIHandler
	ApiEndpoint string
	ApiRoutes   APIRouter
	ApiBusiness APIBusiness
}

type AUTH struct {
	ApiHandler  AuthHandler
	ApiEndpoint string
	ApiRoutes   AuthRouter
	ApiBusiness AuthBusiness
}

func NewAPI(endpoint string, postgres *db.DatabaseConnection, routes APIRouter, handlers APIHandler, business APIBusiness, echo *echo.Echo, authAPI *AUTH) *API {
	newAPI := &API{
		ApiEndpoint: endpoint,
		ApiHandler:  handlers,
		ApiRoutes:   routes,
		ApiBusiness: business,
	}
	newAPI.ApiRoutes.Connect(newAPI.ApiEndpoint, newAPI.ApiHandler, echo, authAPI.ApiHandler)
	newAPI.ApiHandler.Connect(newAPI.ApiBusiness)
	newAPI.ApiBusiness.Connect(postgres)
	return newAPI
}

func NewAUTH(endpoint string, postgres *db.DatabaseConnection, routes AuthRouter, handlers AuthHandler, business AuthBusiness, echo *echo.Echo) *AUTH {
	newAPI := &AUTH{
		ApiEndpoint: endpoint,
		ApiHandler:  handlers,
		ApiRoutes:   routes,
		ApiBusiness: business,
	}
	newAPI.ApiRoutes.Connect(newAPI.ApiEndpoint, newAPI.ApiHandler, echo)
	newAPI.ApiHandler.Connect(newAPI.ApiBusiness)
	newAPI.ApiBusiness.Connect(postgres)
	return newAPI
}
EOF


# Create directories if they do not exist
mkdir -p business
mkdir -p handlers
mkdir -p routes
mkdir -p structs

touch business/auth.go
touch handlers/auth.go
touch routes/auth.go
touch structs/auth.go

cat << EOF > business/auth.go
package business

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"example.com/db"
	"example.com/extras"
	"example.com/structs"
	"github.com/golang-jwt/jwt"
)

type AuthBusiness struct {
	dbCon *db.DatabaseConnection
}

func NewAuthBusiness() *AuthBusiness {
	return &AuthBusiness{}
}
func (b *AuthBusiness) Connect(dbConnection *db.DatabaseConnection) error {
	b.dbCon = dbConnection
	return nil
}
func (b *AuthBusiness) Authentication(email string, password string) (interface{}, error) {

	hash := md5.Sum([]byte(password))
	hashPassword := hex.EncodeToString(hash[:])

	query := fmt.Sprintf("SELECT userguid, fullname, profilepic,email,password, usertype, login_token  FROM tbl_users where (LOWER(email) = LOWER('%s') or LOWER(contact) = LOWER('%s')) AND password = '%s'", email, email, hashPassword)
	rowsRs, err := b.dbCon.Con.Query(query)

	resErr := structs.Response{
		Valid:   false,
		Message: "Auth Failed!",
		Data:    nil,
	}

	if err != nil {
		resErr.Message = "Auth Failed!" + err.Error()
		return resErr, err
	}
	defer rowsRs.Close()

	// creates placeholder of the Credentials
	results := make([]structs.Credentials, 0)

	// we loop through the values of rows
	for rowsRs.Next() {
		obj := structs.Credentials{}
		// err := rowsRs.Scan(&snb.FullName, &snb.OwnerGuid, &snb.Contact, &snb.PIN, &snb.ProfilePic, &snb.Email, &snb.Password)
		err := rowsRs.Scan(&obj.UserGuid, &obj.FullName, &obj.ProfilePic, &obj.Email, &obj.Password, &obj.UserType, &obj.Login_Token)
		if err != nil {
			resErr.Message = err.Error()
			return resErr, err

		}
		results = append(results, obj)
	}

	if err = rowsRs.Err(); err != nil {
		resErr.Message = err.Error()
		return resErr, err

	}

	// result is array of objects
	if len(results) < 1 {
		resErr.Message = "Data not received"
		return resErr, err

	} else {

		secretKey := extras.GetSecretKey()

		secretKeyQuery := \`UPDATE tbl_users SET login_token = $1 WHERE userguid = $2;\`
		_, err := b.dbCon.Con.Exec(secretKeyQuery, secretKey, results[0].UserGuid)

		if err != nil {
			resErr.Message = err.Error()
		}

		// make jwt token
		claims := jwt.MapClaims{}
		claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Token will expire in 24 hours
		claims["userguid"] = results[0].UserGuid
		claims["email"] = results[0].Email

		// Create the token using the claims and a secret key
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signedToken, err := token.SignedString([]byte(secretKey))

		if err != nil {
			resErr.Message = err.Error()
			return resErr, err

		}

		resUser := structs.ResponseUserWithToken{
			Name:       results[0].FullName,
			ProfilePic: results[0].ProfilePic,
			Email:      results[0].Email,
			Token:      signedToken + " " + results[0].UserGuid,
		}

		res := structs.Response{
			Valid:   true,
			Message: results[0].UserType,
			Data:    resUser,
		}

		return res, nil
	}
}

func (b *AuthBusiness) Authenticate(userGuid string, token string) (error, string, string) {

	var (
		JWT_KEY         string
		updatedUserGuid string
		role            string
	)

	err := b.dbCon.Con.QueryRow("SELECT login_token, userguid, usertype FROM tbl_users WHERE userguid = $1", userGuid).Scan(&JWT_KEY, &updatedUserGuid, &role)
	if err == sql.ErrNoRows {
		return errors.New("auth Failed2"), "", ""
	} else if err != nil {
		return errors.New("server Error"), "", ""
	}


	if JWT_KEY != "" {
		claims := &jwt.StandardClaims{}
		_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(JWT_KEY), nil
		})
		if err != nil {
			return errors.New("auth Failed3"), "", ""
		}

		return nil, updatedUserGuid, role //
	} else {
		return errors.New("auth Failed5"), "", ""
	}
}

EOF


cat << EOF > handlers/auth.go
package handlers

import (
	"errors"
	"net/http"
	"strings"

	// "errors"
	// "example.com/business"
	"example.com/apis"
	"example.com/extras"
	"example.com/structs"
	"github.com/labstack/echo/v4"
	// "github.com/dgrijalva/jwt-go"
)

type AuthHandlers struct {
	authBusiness apis.AuthBusiness
}

func NewAuthHandler() *AuthHandlers {
	return &AuthHandlers{}
}

// @Summary Register new user
// @Description
// @Accept json
// @Param  profile body structs.MyAuth true "Register user"
// @Success 200 {object} structs.Response
// @Router /auth [post]
// @Tags auth
func (h *AuthHandlers) Authentication(ec echo.Context) error {
	body := extras.GetJSONRawBody(ec)
	// extras.LogThisWithActor(i.e, "", body["email"].(string))

	email := body["email"].(string)
	password := body["password"].(string)

	data, err := h.authBusiness.Authentication(email, password)
	if err != nil {
		return ec.JSON(http.StatusBadRequest, data)
	}
	return ec.JSON(http.StatusOK, data)
}

// Authenticate wraps a function with authentication logic.
func (h *AuthHandlers) Authenticate(f func(ec echo.Context) error, role ...string) func(ec echo.Context) error {
	return func(ec echo.Context) error {
		// get headers
		authHeader := ec.Request().Header.Get("Authorization")
		if authHeader == "" {
			return errors.New("auth Failed1")
		}
		splitHeader := strings.Split(authHeader, " ")

		userGuid := splitHeader[2]
		token := splitHeader[1]

		err, userGuid, returnedRole := h.authBusiness.Authenticate(userGuid, token)

		if err != nil {

			res := structs.Response{
				Valid:   false,
				Message: "UnAuthorized Request1",
				Data:    nil,
			}
			return ec.JSON(http.StatusUnauthorized, res)
		}

		if !extras.Contains(role, returnedRole) {
			res := structs.Response{
				Valid:   false,
				Message: "UnAuthorized Request2",
				Data:    nil,
			}

			return ec.JSON(http.StatusUnauthorized, res)
		}

		ec.Set("user_guid", userGuid)
		// Proceed with the original function if authentication is successful
		return f(ec)
	}
}

// Connect is required to fulfill the apis.AuthHandler interface
func (h *AuthHandlers) Connect(business apis.AuthBusiness) error {
	h.authBusiness = business
	return nil
}

func (h *AuthHandlers) Middleware(f func(ec echo.Context) error) func(ec echo.Context) error {
	return func(ec echo.Context) error {
		// if err := h.CheckAuth(ec); err != nil {
		// 	res := structs.Response{
		// 		Valid:   false,
		// 		Message: err.Error(),
		// 		Data:    nil,
		// 	}
		// 	return ec.JSON(http.StatusForbidden, res)
		// }
		return f(ec)
	}
}

func (h *AuthHandlers) Decorate(f func(ec echo.Context) error) func(ec echo.Context) error {
	return func(ec echo.Context) error {
		return f(ec)
	}
}

EOF


cat << EOF > routes/auth.go
package routes

import (
	"example.com/apis"
	"github.com/labstack/echo/v4"
)

type AuthRoutes struct {
}

func NewAuthRoutes() *AuthRoutes {
	return &AuthRoutes{}
}

func (r *AuthRoutes) Connect(endPoint string, AuthHandler apis.AuthHandler, echo *echo.Echo) error {
	echo.POST(endPoint, AuthHandler.Authentication)

	return nil
}

EOF


cat << EOF > structs/auth.go
package structs

type MyAuth struct {
	Email    string \`json:"email"\`
	Password string \`json:"password"\`
}

type Auth struct {
	Email      string \`json:"email"\`
	Password   string \`json:"password"\`
	UserGuid   string \`json:"user_guid"\`
	LoginToken string \`json:"login_token"\`
}

type Authenticate struct {
	Token string \`json:"token"\`
}
type Response struct {
	Valid   bool        \`json:"valid"\`
	Message string      \`json:"message"\`
	Data    interface{} \`json:"data"\`
}
type ResponseUserWithToken struct {
	// UserGuid   string \`json:"userguid"\`
	Name       string \`json:"name"\`
	ProfilePic string \`json:"profilepic"\`
	Email      string \`json:"email"\`
	Token      string \`json:"token"\`
}

type Credentials struct {
	UserGuid    string \`json:"userguid"\`
	FullName    string \`json:"fullname"\`
	ProfilePic  string \`json:"profilepic"\`
	Email       string \`json:"email"\`
	Password    string \`json:"password"\`
	UserType    string \`json:"usertype"\`
	Login_Token string \`json:"login_token"\`
}

EOF





touch main.go

cat << EOF > main.go

package main

import (
	"fmt"
	"os"
	"os/signal"

	"example.com/apis"
	"example.com/business"
	"example.com/db"
	_ "example.com/docs" // docs is generated by Swag CLI, you have to import it.
	"example.com/handlers"
	"example.com/routes"
	"github.com/labstack/echo/v4"
	echoSwagger "github.com/swaggo/echo-swagger" // echo-swagger middleware
)

// @title Swagger Example API
// @version 1.0
// @description This is a sample server Petstore server.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description "Bearer token"

func main() {

	e := echo.New()

	postgres := db.NewDatabaseConnection()

	authAPI := apis.NewAUTH("/auth",
		postgres,
		routes.NewAuthRoutes(),
		handlers.NewAuthHandler(),
		business.NewAuthBusiness(), e)

	_ = authAPI
	//	apis.NewAPI("/product",
	//		postgres,
	//		routes.NewProductRoutes(),
	//		handlers.NewProductHandler(),
	//		business.NewProductBusiness(), e, authAPI)

	// Serve the Swagger UI
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	sigChannel := make(chan os.Signal)
	signal.Notify(sigChannel, os.Interrupt)
	signal.Notify(sigChannel, os.Kill)

	go func() {
		e.Start(":8081")
	}()

	<-sigChannel
	postgres.Con.Close()
	fmt.Println("Database connection closed!")

}
EOF


mkdir -p db
touch db/main.go

cat << EOF > db/main.go
package db

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"time"

	_ "github.com/lib/pq"

	"example.com/extras"
)

type DatabaseConnection struct {
	psqlInfo      string
	Con           *sql.DB
	lastConnected time.Time
}

func NewDatabaseConnection() *DatabaseConnection {
	psqlInfo := ""
	isLocal, err := strconv.ParseBool(extras.GetEnv("isLocal"))
	if err != nil {
		log.Fatal("ERROR: unable to convert isLocal to boolean", err)
	}
	if isLocal {
		var (
			host      = extras.GetEnv("localHost")
			port, err = strconv.Atoi(extras.GetEnv("localPort"))
			user      = extras.GetEnv("localUser")
			password  = extras.GetEnv("localPassword")
			dbname    = extras.GetEnv("localDbname")
		)
		if err != nil {
			log.Fatal("ERROR: Port unable to convert port to int", err)
		}

		psqlInfo = fmt.Sprintf("host=%s port=%d user=%s "+
			"password=%s dbname=%s sslmode=disable",
			host, port, user, password, dbname)
		// psqlInfo = "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbname
		log.Println("Connected to local DB")
	} else {
		var (
			host     = extras.GetEnv("liveHost")
			port     = extras.GetEnv("livePort")
			user     = extras.GetEnv("liveUser")
			password = extras.GetEnv("livePassword")
			dbname   = extras.GetEnv("liveDbname")
		)
		psqlInfo = fmt.Sprintf("host=%s port=%s user=%s "+
			"password=%s dbname=%s sslmode=require",
			host, port, user, password, dbname)
		// psqlInfo = "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbname
		log.Println("Connected to production DB")
	}
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		// log.Fatal("Error Connecting to DB", err)
		panic(err)
	} else if err := db.Ping(); err != nil {
		panic(err)
	}
	// defer db.Close()
	return &DatabaseConnection{
		psqlInfo:      psqlInfo,
		Con:           db,
		lastConnected: time.Now(),
	}
}

func (db *DatabaseConnection) HandleReconnect() error {
	db.Con.Close()
	tempdb, err := sql.Open("postgres", db.psqlInfo)
	if err != nil {
		// return fmt.Errorf("Error Reconnecting to DB", err)
		panic(err)
	} else if err := tempdb.Ping(); err != nil {
		panic(err)
	}
	// defer tempdb.Close()
	db.Con = tempdb
	db.lastConnected = time.Now()
	return nil
}

func (db *DatabaseConnection) CheckTimeOut() error {
	passedTime := time.Since(db.lastConnected).Seconds()
	if (passedTime) > 10 {
		err := db.HandleReconnect()
		if err != nil {
			return err
		}
		return fmt.Errorf("format string", db.psqlInfo)
		// return fmt.Errorf("Reconnecting the DB....", passedTime)
	}
	return nil
}
EOF


touch extras/main.go

cat << EOF > extras/main.go
package extras

import (
	"encoding/json"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)


func GetEnv(key string) string {
	viper.SetConfigFile(".env")

	err := viper.ReadInConfig()

	if err != nil {
		log.Fatalf("Error while reading config file %s", err)
	}
	value, ok := viper.Get(key).(string)
	if !ok {
		log.Fatalf("Invalid type assertion")
	}

	return value
}

func Contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func ConvertDashesToUnderscores(input string) string {
	return strings.ReplaceAll(input, "-", "_")
}

func GetTypeForColumn(datatype string) string {
	if datatype == "Short Text" {
		return "VARCHAR(100)"
	} else if datatype == "Paragraph" {
		return "TEXT"
	} else if datatype == "Multiple choice" {
		return "TEXT"
	} else if datatype == "Yes/No" {
		return "INT"
	} else if datatype == "Checkbox" {
		return "TEXT"
	} else if datatype == "File upload" {
		return "TEXT"
	} else if datatype == "Multiple choice grid" {
		return "TEXT"
	} else if datatype == "Date" {
		return "DATE"
	} else if datatype == "Time" {
		return "TIME"
	} else if datatype == "Phone number" {
		return "VARCHAR(100)"
	} else if datatype == "Address" {
		return "VARCHAR(500)"
	} else if datatype == "Location" {
		return "VARCHAR(500)"
	} else if datatype == "Document" {
		return "TEXT"
	} else if datatype == "End screen" {
		return "INT"
	}
	return ""
}

// get secretkey
func GetSecretKey() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 8
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func GetJSONRawBody(c echo.Context) map[string]interface{} {

	jsonBody := make(map[string]interface{})
	err := json.NewDecoder(c.Request().Body).Decode(&jsonBody)
	if err != nil {

		// log.Error("empty json body")
		return nil
	}

	return jsonBody
}

EOF

touch Makefile

cat << EOF > Makefile
build:
	go build -o bin/main main.go

run:
	go run main.go

buildandrun: build
	./bin/main

EOF

echo "=========================================="
echo ''
echo "./builder.sh <Component name>"
echo "first letter of Component Should be Uppercase"
echo ''
echo "=========================================="
echo "paste the following lines in .env"


echo ''
echo '# local postgres'
echo 'localHost="localhost"'
echo 'localPort="5432"'
echo 'localUser="<localuser>"'
echo 'localPassword="<localpassword>"'
echo 'localDbname="<localdb>"'

echo ''
echo '# live postgrer'
echo 'liveHost="<liveServer>"'
echo 'livePort="5432"'
echo 'liveUser="<liveuser>"'
echo 'livePassword="<password>"'
echo 'liveDbname="<db>"'

echo ''
echo "=========================================="
echo "Run the following Commands by copying and pasting"

echo "=========================================="
echo "go mod init example.com"
echo "go get -u github.com/swaggo/swag/cmd/swag"
echo "go get -u github.com/swaggo/echo-swagger"
echo "go get github.com/golang-jwt/jwt"
echo "go get github.com/spf13/viper"
echo "go get github.com/labstack/echo"
echo "go get github.com/aws/aws-sdk-go/aws"
echo "go get github.com/anthdm/hollywood/actor"
echo "swag init"
echo "go mod tidy"
echo "make run"

