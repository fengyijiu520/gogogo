package main

import (
    "fmt"
    "skill-scanner/internal/storage"
    "skill-scanner/internal/models"
)

func main() {
    store, err := storage.NewStore("./data")
    if err != nil {
        fmt.Printf("Store error: %v\n", err)
        return
    }
    
    users := store.ListUsers()
    fmt.Printf("Users count: %d\n", len(users))
    for _, u := range users {
        fmt.Printf("  User: username=%s team=%s role=%s\n", u.Username, u.Team, u.Role)
    }
    
    fmt.Printf("CheckPassword admin/admin123: %v\n", store.CheckPassword("admin", "admin123"))
    fmt.Printf("CheckPassword newuser/wrong: %v\n", store.CheckPassword("newuser", "wrong"))
    
    logs := store.ListLoginLogs()
    fmt.Printf("Login logs: %d\n", len(logs))
    for _, l := range logs {
        fmt.Printf("  Log: user=%s result=%s ip=%s\n", l.Username, l.Result, l.IP)
    }
    
    admin := store.GetUser("admin")
    fmt.Printf("Admin HasPermission(PermUserManagement): %v\n", admin.HasPermission(models.PermUserManagement))
    fmt.Printf("Admin HasPermission(PermLoginLog): %v\n", admin.HasPermission(models.PermLoginLog))
    
    nu := store.GetUser("newuser")
    fmt.Printf("newuser HasPermission(PermUserManagement): %v\n", nu.HasPermission(models.PermUserManagement))
    fmt.Printf("newuser HasPermission(PermLoginLog): %v\n", nu.HasPermission(models.PermLoginLog))
}
