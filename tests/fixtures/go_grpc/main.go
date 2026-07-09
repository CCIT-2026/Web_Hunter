// Fixture: Go service with gRPC and basic HTTP
package main

import (
    "net/http"
    "github.com/gin-gonic/gin"
    "google.golang.org/grpc"
)

func main() {
    // HTTP endpoints
    r := gin.Default()
    r.GET("/api/health", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })
    r.POST("/api/data", func(c *gin.Context) {
        url := c.PostForm("url")
        // SSRF: outbound request on user input
        resp, _ := http.Get(url)
        _ = resp
        c.JSON(200, gin.H{"ok": true})
    })
    go r.Run(":8080")

    // gRPC server
    s := grpc.NewServer()
    _ = s
    // listener would be set up here
}
