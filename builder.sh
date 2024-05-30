#!/bin/bash
a=$(echo $1 | sed 's/\([A-Z]\)/_\1/g' | tr '[:upper:]' '[:lower:]' | sed 's/^_//')


# Create directories if they do not exist
mkdir -p business
mkdir -p handlers
mkdir -p routes
mkdir -p structs

touch business/${a}.go
touch handlers/${a}.go
touch routes/${a}.go
touch structs/${a}.go

cat << EOF > business/${a}.go
package business

import (
	"example.com/db"
	"example.com/structs"
)

type ${1}Business struct {
	dbCon *db.DatabaseConnection
}

func New${1}Business() *${1}Business {
	return &${1}Business{}
}

func (b *${1}Business) Connect(dbConnection *db.DatabaseConnection) error {
	b.dbCon = dbConnection
	return nil
}

func (b *${1}Business) GET(data interface{}) (interface{}, error) {
	${a}s := structs.${1}s{
		My${1}s: []structs.${1}{
		},
	}
	return ${a}s, nil
}
func (b *${1}Business) GETBYID(data interface{}) (interface{}, error) {
	${a}, _ := data.(structs.${1})
	return ${a}, nil
}
func (b *${1}Business) POST(data interface{}) (interface{}, error) {
	${a}, _ := data.(structs.${1})
	return ${a}, nil
}
func (b *${1}Business) MULTIPOST(data interface{}) (interface{}, error) {
	${a}, _ := data.(structs.${1})
	return ${a}, nil
}
func (b *${1}Business) PUT(data interface{}) (interface{}, error) {
	${a}, _ := data.(structs.${1})
	return ${a}, nil
}
func (b *${1}Business) DELETE(data interface{}) (interface{}, error) {
	${a}, _ := data.(structs.${1})
	return ${a}, nil
}
EOF


cat << EOF > handlers/${a}.go
package handlers

import (
	"net/http"

	"example.com/apis"
	"example.com/structs"
	"github.com/labstack/echo/v4"
)

type ${1}Handlers struct {
	apiBusiness apis.APIBusiness
}

func New${1}Handler() *${1}Handlers {
	return &${1}Handlers{}
}

func (h *${1}Handlers) Connect(business apis.APIBusiness) error {
	h.apiBusiness = business
	return nil
}

// @Summary Get ${a}
// @Description
// @Produce json
// @Success 200 {object} structs.${1} "${a}"
// @Router /${a} [get]
// @Security ApiKeyAuth
// @Tags ${a}
func (h *${1}Handlers) GET(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, structs.Response{Message: "Get ${1}", Valid: true, Data: nil})
}

// @Summary Post ${a}
// @Description
// @Produce json
// @Param  product body structs.${1} true "Post ${a}"
// @Success 200 {object} structs.Response
// @Router /${a} [post]
// @Security ApiKeyAuth
// @Tags ${a}
func (h *${1}Handlers) POST(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, structs.Response{Message: "Post ${1}", Valid: true, Data: nil})
}

// @Summary Put ${a}
// @Description
// @Produce json
// @Param  product body structs.${1} true "Put ${a}"
// @Success 200 {object} structs.Response
// @Router /${a} [put]
// @Security ApiKeyAuth
// @Tags ${a}
func (h *${1}Handlers) PUT(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, structs.Response{Message: "Put ${1}", Valid: true, Data: nil})
}

// @Summary Delete ${a}
// @Description
// @Produce json
// @Param  product body structs.${1} true "Delete ${a}"
// @Success 200 {object} structs.Response
// @Router /${a} [delete]
// @Security ApiKeyAuth
// @Tags ${a}
func (h *${1}Handlers) DELETE(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, structs.Response{Message: "Delete ${1}", Valid: true, Data: nil})
}

// @Summary Get ${a} by id
// @Description
// @Produce json
// @Param id path string true "id"
// @Success 200 {object} structs.${1} "${a}"
// @Router /${a}/{id} [get]
// @Security ApiKeyAuth
// @Tags ${a}
func (h *${1}Handlers) GETBYID(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, structs.Response{Message: "Get ${a} by id", Valid: true, Data: nil})
}

// @Summary Multipost ${a}
// @Description
// @Produce json
// @Param  product body structs.${1}s true "Multipost ${a}"
// @Success 200 {object} structs.Response
// @Router /${a}/multi [post]
// @Security ApiKeyAuth
// @Tags ${a}
func (h *${1}Handlers) MULTIPOST(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, structs.Response{Message: "Multipost ${1}", Valid: true, Data: nil})
}

EOF


cat << EOF > routes/${a}.go
package routes

import (
	"example.com/apis"
	"github.com/labstack/echo/v4"
)

type ${1}Routes struct {
}

func New${1}Routes() *${1}Routes {
	return &${1}Routes{}
}

func (r *${1}Routes) Connect(endPoint string, ${a}Handler apis.APIHandler, echo *echo.Echo, auth apis.AuthHandler) error {
	// echo.GET(endPoint, auth.Authenticate(${a}Handler.GET)) // to authenticate the user
	echo.GET(endPoint, ${a}Handler.GET)
	echo.POST(endPoint, ${a}Handler.POST)
	echo.PUT(endPoint, ${a}Handler.PUT)
	echo.DELETE(endPoint, ${a}Handler.DELETE)
	echo.GET(endPoint+"/:id", ${a}Handler.GETBYID)
	echo.POST(endPoint+"/multi", ${a}Handler.MULTIPOST)
	return nil
}

EOF


cat << EOF > structs/${a}.go
package structs

type ${1}s struct {
	My${1}s []${1} \`json:"${a}s"\`
}

type ${1} struct {
	${1}Id   string \`json:"${a}_id"\`
	${1}Name string \`json:"${a}_name"\`
}

EOF

swag init

echo "Copy these lines in your main.go file"

echo "=========================================="
echo ""
echo "apis.NewAPI(\"/${a}\","
echo "    postgres,"
echo "    routes.New${1}Routes(),"
echo "    handlers.New${1}Handler(),"
echo "    business.New${1}Business(), e, authAPI)"
echo ""
echo "=========================================="


# ./builder.sh <Component name>   
# first letter of Component Should be Uppercase
