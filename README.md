# Spring_RestAPI_Creations
spring rest call development. happy coding. 

```java

// =====================================
// STUDENT CRUD API CONTROLLER
// Demonstrates: @PathVariable, @RequestParam, @RequestBody, Headers, Cookies, Sessions
// =====================================
package com.demo.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.time.LocalDateTime;
import java.util.*;

@RestController
@RequestMapping("/api/students")
@CrossOrigin(origins = "*")
public class StudentController {
    
    // In-memory storage for demo (your students will use actual service)
    private Map<Long, Map<String, Object>> students = new HashMap<>();
    private Long nextId = 1L;
    
    // =====================================
    // CREATE - POST with @RequestBody
    // =====================================
    @PostMapping
    public ResponseEntity<?> createStudent(
            @Valid @RequestBody Map<String, Object> studentData,
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestHeader(value = "X-Client-Version", defaultValue = "1.0") String clientVersion,
            @RequestHeader HttpHeaders headers,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        try {
            // Log all headers for demonstration
            System.out.println("=== CREATE STUDENT - Headers ===");
            headers.forEach((key, value) -> System.out.println(key + ": " + value));
            
            // Validate auth header
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Authorization header required", "code", 401));
            }
            
            // Create student
            Long id = nextId++;
            studentData.put("id", id);
            studentData.put("createdAt", LocalDateTime.now());
            studentData.put("updatedAt", LocalDateTime.now());
            students.put(id, studentData);
            
            // Set response headers
            response.setHeader("X-Resource-Created", "true");
            response.setHeader("X-Resource-ID", id.toString());
            response.setHeader("X-Client-Version", clientVersion);
            
            // Set cookie for tracking
            Cookie trackingCookie = new Cookie("STUDENT_CREATED", id.toString());
            trackingCookie.setMaxAge(3600); // 1 hour
            trackingCookie.setPath("/");
            response.addCookie(trackingCookie);
            
            // Create session data
            HttpSession session = request.getSession(true);
            session.setAttribute("lastCreatedStudent", id);
            session.setAttribute("createdAt", LocalDateTime.now());
            
            return ResponseEntity.status(HttpStatus.CREATED)
                .header("Location", "/api/students/" + id)
                .body(Map.of(
                    "success", true,
                    "message", "Student created successfully",
                    "data", studentData,
                    "sessionId", session.getId()
                ));
                
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", e.getMessage(), "code", 400));
        }
    }
    
    // =====================================
    // READ - GET with @PathVariable
    // =====================================
    @GetMapping("/{id}")
    public ResponseEntity<?> getStudentById(
            @PathVariable Long id,
            @RequestHeader(value = "Accept", defaultValue = "application/json") String acceptHeader,
            @RequestHeader(value = "User-Agent", required = false) String userAgent,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        System.out.println("=== GET STUDENT BY ID ===");
        System.out.println("Path Variable ID: " + id);
        System.out.println("Accept Header: " + acceptHeader);
        System.out.println("User Agent: " + userAgent);
        
        // Check session
        HttpSession session = request.getSession(false);
        String sessionInfo = "No active session";
        if (session != null) {
            sessionInfo = "Session ID: " + session.getId() + 
                         ", Last Created: " + session.getAttribute("lastCreatedStudent");
        }
        
        // Check cookies
        Map<String, String> cookieData = new HashMap<>();
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                cookieData.put(cookie.getName(), cookie.getValue());
            }
        }
        
        Map<String, Object> student = students.get(id);
        if (student == null) {
            response.setStatus(HttpStatus.NOT_FOUND.value());
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of(
                    "error", "Student not found with ID: " + id,
                    "code", 404,
                    "sessionInfo", sessionInfo,
                    "cookies", cookieData
                ));
        }
        
        // Set response headers
        response.setHeader("X-Resource-Found", "true");
        response.setHeader("X-Last-Modified", student.get("updatedAt").toString());
        response.setHeader("Cache-Control", "max-age=300"); // 5 minutes cache
        
        return ResponseEntity.ok()
            .header("X-Session-Info", sessionInfo)
            .body(Map.of(
                "success", true,
                "data", student,
                "sessionInfo", sessionInfo,
                "cookies", cookieData,
                "requestInfo", Map.of(
                    "method", request.getMethod(),
                    "uri", request.getRequestURI(),
                    "remoteAddr", request.getRemoteAddr()
                )
            ));
    }
    
    // =====================================
    // READ ALL - GET with @RequestParam (Pagination, Filtering, Sorting)
    // =====================================
    @GetMapping
    public ResponseEntity<?> getAllStudents(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "asc") String sortOrder,
            @RequestParam(required = false) String name,
            @RequestParam(required = false) String course,
            @RequestParam(required = false) Integer minAge,
            @RequestParam(required = false) Integer maxAge,
            @RequestParam(required = false) String search,
            @RequestHeader(value = "X-Request-ID", required = false) String requestId,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        System.out.println("=== GET ALL STUDENTS - Request Params ===");
        System.out.println("Page: " + page + ", Size: " + size);
        System.out.println("Sort By: " + sortBy + ", Order: " + sortOrder);
        System.out.println("Filters - Name: " + name + ", Course: " + course);
        System.out.println("Age Range: " + minAge + " - " + maxAge);
        System.out.println("Search: " + search);
        System.out.println("Request ID: " + requestId);
        
        // Get all query parameters
        Map<String, String[]> allParams = request.getParameterMap();
        System.out.println("All Parameters: " + allParams);
        
        List<Map<String, Object>> filteredStudents = new ArrayList<>(students.values());
        
        // Apply filters based on request parameters
        if (name != null && !name.isEmpty()) {
            filteredStudents = filteredStudents.stream()
                .filter(s -> s.get("name").toString().toLowerCase().contains(name.toLowerCase()))
                .toList();
        }
        
        if (course != null && !course.isEmpty()) {
            filteredStudents = filteredStudents.stream()
                .filter(s -> course.equals(s.get("course")))
                .toList();
        }
        
        if (minAge != null) {
            filteredStudents = filteredStudents.stream()
                .filter(s -> (Integer) s.get("age") >= minAge)
                .toList();
        }
        
        if (maxAge != null) {
            filteredStudents = filteredStudents.stream()
                .filter(s -> (Integer) s.get("age") <= maxAge)
                .toList();
        }
        
        if (search != null && !search.isEmpty()) {
            filteredStudents = filteredStudents.stream()
                .filter(s -> s.get("name").toString().toLowerCase().contains(search.toLowerCase()) ||
                           s.get("course").toString().toLowerCase().contains(search.toLowerCase()))
                .toList();
        }
        
        // Pagination simulation
        int totalElements = filteredStudents.size();
        int startIndex = page * size;
        int endIndex = Math.min(startIndex + size, totalElements);
        
        List<Map<String, Object>> paginatedStudents = startIndex < totalElements ? 
            filteredStudents.subList(startIndex, endIndex) : new ArrayList<>();
        
        // Set response headers
        response.setHeader("X-Total-Count", String.valueOf(totalElements));
        response.setHeader("X-Page", String.valueOf(page));
        response.setHeader("X-Size", String.valueOf(size));
        response.setHeader("X-Total-Pages", String.valueOf((totalElements + size - 1) / size));
        response.setHeader("X-Request-ID", requestId != null ? requestId : UUID.randomUUID().toString());
        
        return ResponseEntity.ok()
            .body(Map.of(
                "success", true,
                "data", paginatedStudents,
                "pagination", Map.of(
                    "page", page,
                    "size", size,
                    "totalElements", totalElements,
                    "totalPages", (totalElements + size - 1) / size
                ),
                "filters", Map.of(
                    "name", name != null ? name : "",
                    "course", course != null ? course : "",
                    "minAge", minAge != null ? minAge : "",
                    "maxAge", maxAge != null ? maxAge : "",
                    "search", search != null ? search : ""
                ),
                "sorting", Map.of(
                    "sortBy", sortBy,
                    "sortOrder", sortOrder
                )
            ));
    }
    
    // =====================================
    // UPDATE - PUT with @PathVariable and @RequestBody
    // =====================================
    @PutMapping("/{id}")
    public ResponseEntity<?> updateStudent(
            @PathVariable Long id,
            @Valid @RequestBody Map<String, Object> updateData,
            @RequestHeader(value = "If-Match", required = false) String ifMatch,
            @RequestHeader(value = "X-Update-Source", defaultValue = "API") String updateSource,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        System.out.println("=== UPDATE STUDENT ===");
        System.out.println("Path Variable ID: " + id);
        System.out.println("Update Source: " + updateSource);
        System.out.println("If-Match Header: " + ifMatch);
        
        Map<String, Object> existingStudent = students.get(id);
        if (existingStudent == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", "Student not found with ID: " + id, "code", 404));
        }
        
        // Check If-Match header for optimistic locking simulation
        if (ifMatch != null && !ifMatch.equals(existingStudent.get("updatedAt").toString())) {
            return ResponseEntity.status(HttpStatus.PRECONDITION_FAILED)
                .body(Map.of("error", "Resource has been modified", "code", 412));
        }
        
        // Update student data
        updateData.forEach((key, value) -> {
            if (!key.equals("id") && !key.equals("createdAt")) {
                existingStudent.put(key, value);
            }
        });
        existingStudent.put("updatedAt", LocalDateTime.now());
        
        // Set response headers
        response.setHeader("X-Resource-Updated", "true");
        response.setHeader("X-Update-Source", updateSource);
        response.setHeader("ETag", existingStudent.get("updatedAt").toString());
        
        // Update session
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.setAttribute("lastUpdatedStudent", id);
            session.setAttribute("updatedAt", LocalDateTime.now());
        }
        
        return ResponseEntity.ok()
            .header("Last-Modified", existingStudent.get("updatedAt").toString())
            .body(Map.of(
                "success", true,
                "message", "Student updated successfully",
                "data", existingStudent,
                "updateSource", updateSource
            ));
    }
    
    // =====================================
    // PARTIAL UPDATE - PATCH with @PathVariable and @RequestBody
    // =====================================
    @PatchMapping("/{id}")
    public ResponseEntity<?> partialUpdateStudent(
            @PathVariable Long id,
            @RequestBody Map<String, Object> patchData,
            @RequestHeader(value = "Content-Type", defaultValue = "application/json") String contentType,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        System.out.println("=== PARTIAL UPDATE STUDENT ===");
        System.out.println("Path Variable ID: " + id);
        System.out.println("Content-Type: " + contentType);
        System.out.println("Patch Data: " + patchData);
        
        Map<String, Object> existingStudent = students.get(id);
        if (existingStudent == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", "Student not found with ID: " + id, "code", 404));
        }
        
        // Apply partial updates only to provided fields
        Map<String, Object> updatedFields = new HashMap<>();
        patchData.forEach((key, value) -> {
            if (!key.equals("id") && !key.equals("createdAt") && value != null) {
                existingStudent.put(key, value);
                updatedFields.put(key, value);
            }
        });
        existingStudent.put("updatedAt", LocalDateTime.now());
        
        response.setHeader("X-Patch-Applied", "true");
        response.setHeader("X-Updated-Fields", updatedFields.keySet().toString());
        
        return ResponseEntity.ok()
            .body(Map.of(
                "success", true,
                "message", "Student partially updated",
                "data", existingStudent,
                "updatedFields", updatedFields
            ));
    }
    
    // =====================================
    // DELETE - DELETE with @PathVariable
    // =====================================
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteStudent(
            @PathVariable Long id,
            @RequestHeader(value = "X-Confirm-Delete", defaultValue = "false") String confirmDelete,
            @RequestParam(defaultValue = "false") boolean force,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        System.out.println("=== DELETE STUDENT ===");
        System.out.println("Path Variable ID: " + id);
        System.out.println("Confirm Delete Header: " + confirmDelete);
        System.out.println("Force Parameter: " + force);
        
        if (!confirmDelete.equals("true") && !force) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of(
                    "error", "Deletion not confirmed", 
                    "code", 400,
                    "hint", "Set X-Confirm-Delete header to 'true' or force=true parameter"
                ));
        }
        
        Map<String, Object> deletedStudent = students.remove(id);
        if (deletedStudent == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", "Student not found with ID: " + id, "code", 404));
        }
        
        // Set response headers
        response.setHeader("X-Resource-Deleted", "true");
        response.setHeader("X-Deleted-At", LocalDateTime.now().toString());
        
        // Clear related cookies
        Cookie clearCookie = new Cookie("STUDENT_CREATED", "");
        clearCookie.setMaxAge(0);
        clearCookie.setPath("/");
        response.addCookie(clearCookie);
        
        return ResponseEntity.ok()
            .body(Map.of(
                "success", true,
                "message", "Student deleted successfully",
                "deletedData", deletedStudent,
                "deletedAt", LocalDateTime.now()
            ));
    }
}

// =====================================
// AUTHENTICATION & SESSION API CONTROLLER
// =====================================
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    // In-memory user storage for demo
    private Map<String, Map<String, Object>> users = new HashMap<>();
    
    public AuthController() {
        // Add demo users
        users.put("admin", Map.of("username", "admin", "password", "admin123", "role", "ADMIN"));
        users.put("user", Map.of("username", "user", "password", "user123", "role", "USER"));
    }
    
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody Map<String, String> loginData,
            @RequestHeader(value = "User-Agent", required = false) String userAgent,
            @RequestHeader(value = "X-Forwarded-For", required = false) String forwardedFor,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        String username = loginData.get("username");
        String password = loginData.get("password");
        
        System.out.println("=== LOGIN ATTEMPT ===");
        System.out.println("Username: " + username);
        System.out.println("User-Agent: " + userAgent);
        System.out.println("X-Forwarded-For: " + forwardedFor);
        System.out.println("Remote Address: " + request.getRemoteAddr());
        
        Map<String, Object> user = users.get(username);
        if (user == null || !user.get("password").equals(password)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid credentials", "code", 401));
        }
        
        // Create session
        HttpSession session = request.getSession(true);
        session.setAttribute("username", username);
        session.setAttribute("role", user.get("role"));
        session.setAttribute("loginTime", LocalDateTime.now());
        session.setMaxInactiveInterval(1800); // 30 minutes
        
        // Set authentication cookie
        String token = "token_" + username + "_" + System.currentTimeMillis();
        Cookie authCookie = new Cookie("AUTH_TOKEN", token);
        authCookie.setHttpOnly(true);
        authCookie.setMaxAge(1800); // 30 minutes
        authCookie.setPath("/");
        response.addCookie(authCookie);
        
        // Set response headers
        response.setHeader("X-Auth-Success", "true");
        response.setHeader("X-Session-Created", session.getId());
        response.setHeader("X-Token-Expires", String.valueOf(System.currentTimeMillis() + 1800000));
        
        return ResponseEntity.ok()
            .body(Map.of(
                "success", true,
                "message", "Login successful",
                "data", Map.of(
                    "username", username,
                    "role", user.get("role"),
                    "sessionId", session.getId(),
                    "token", token,
                    "expiresIn", 1800
                )
            ));
    }
    
    @GetMapping("/profile")
    public ResponseEntity<?> getProfile(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @CookieValue(value = "AUTH_TOKEN", required = false) String authToken,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        System.out.println("=== GET PROFILE ===");
        System.out.println("Authorization Header: " + authHeader);
        System.out.println("Auth Token Cookie: " + authToken);
        
        HttpSession session = request.getSession(false);
        if (session == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "No active session", "code", 401));
        }
        
        String username = (String) session.getAttribute("username");
        String role = (String) session.getAttribute("role");
        LocalDateTime loginTime = (LocalDateTime) session.getAttribute("loginTime");
        
        if (username == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid session", "code", 401));
        }
        
        response.setHeader("X-Session-Valid", "true");
        response.setHeader("X-Session-Duration", String.valueOf(
            java.time.Duration.between(loginTime, LocalDateTime.now()).getSeconds()));
        
        return ResponseEntity.ok()
            .body(Map.of(
                "success", true,
                "data", Map.of(
                    "username", username,
                    "role", role,
                    "loginTime", loginTime,
                    "sessionId", session.getId(),
                    "maxInactiveInterval", session.getMaxInactiveInterval()
                )
            ));
    }
    
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            HttpServletRequest request,
            HttpServletResponse response) {
        
        HttpSession session = request.getSession(false);
        if (session != null) {
            System.out.println("=== LOGOUT ===");
            System.out.println("Invalidating session: " + session.getId());
            session.invalidate();
        }
        
        // Clear auth cookie
        Cookie authCookie = new Cookie("AUTH_TOKEN", "");
        authCookie.setMaxAge(0);
        authCookie.setPath("/");
        response.addCookie(authCookie);
        
        response.setHeader("X-Session-Cleared", "true");
        response.setHeader("X-Logout-Time", LocalDateTime.now().toString());
        
        return ResponseEntity.ok()
            .body(Map.of(
                "success", true,
                "message", "Logged out successfully"
            ));
    }
}

// =====================================
// ADVANCED FEATURES API CONTROLLER
// =====================================
@RestController
@RequestMapping("/api/advanced")
public class AdvancedController {
    
    @GetMapping("/headers-demo")
    public ResponseEntity<?> headersDemo(
            @RequestHeader HttpHeaders headers,
            @RequestHeader(value = "Accept") String accept,
            @RequestHeader(value = "Accept-Language", defaultValue = "en") String acceptLang,
            @RequestHeader(value = "X-Custom-Header", required = false) String customHeader,
            HttpServletResponse response) {
        
        System.out.println("=== HEADERS DEMO ===");
        
        // Log all headers
        Map<String, List<String>> headerMap = new HashMap<>();
        headers.forEach((key, value) -> {
            headerMap.put(key, value);
            System.out.println(key + ": " + value);
        });
        
        // Set various response headers
        response.setHeader("X-Response-Time", String.valueOf(System.currentTimeMillis()));
        response.setHeader("X-Server-Name", "Demo-Server");
        response.setHeader("X-API-Version", "v1.0");
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Access-Control-Allow-Origin", "*");
        
        return ResponseEntity.ok()
            .header("X-Custom-Response", "Custom-Value")
            .header("X-Processing-Time", "150ms")
            .body(Map.of(
                "receivedHeaders", headerMap,
                "specificHeaders", Map.of(
                    "accept", accept,
                    "acceptLanguage", acceptLang,
                    "customHeader", customHeader != null ? customHeader : "Not provided"
                ),
                "message", "Headers processed successfully"
            ));
    }
    
    @PostMapping("/cookies-demo")
    public ResponseEntity<?> cookiesDemo(
            @CookieValue(value = "sessionId", required = false) String sessionId,
            @CookieValue(value = "preferences", required = false) String preferences,
            @RequestBody(required = false) Map<String, String> cookieData,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        System.out.println("=== COOKIES DEMO ===");
        
        // Read all existing cookies
        Map<String, String> existingCookies = new HashMap<>();
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                existingCookies.put(cookie.getName(), cookie.getValue());
                System.out.println("Cookie: " + cookie.getName() + " = " + cookie.getValue());
            }
        }
        
        // Set new cookies if data provided
        if (cookieData != null) {
            cookieData.forEach((key, value) -> {
                Cookie cookie = new Cookie(key, value);
                cookie.setMaxAge(3600); // 1 hour
                cookie.setPath("/");
                cookie.setHttpOnly(true);
                response.addCookie(cookie);
            });
        }
        
        // Set demonstration cookies
        Cookie demoCookie = new Cookie("demo-cookie", "demo-value-" + System.currentTimeMillis());
        demoCookie.setMaxAge(7200); // 2 hours
        demoCookie.setPath("/");
        response.addCookie(demoCookie);
        
        Cookie secureCookie = new Cookie("secure-cookie", "secure-value");
        secureCookie.setMaxAge(1800); // 30 minutes
        secureCookie.setPath("/");
        secureCookie.setHttpOnly(true);
        secureCookie.setSecure(false); // Set to true in production with HTTPS
        response.addCookie(secureCookie);
        
        return ResponseEntity.ok()
            .body(Map.of(
                "existingCookies", existingCookies,
                "newCookiesSet", cookieData != null ? cookieData.keySet() : Set.of(),
                "demoCookiesAdded", List.of("demo-cookie", "secure-cookie"),
                "message", "Cookies processed successfully"
            ));
    }
    
    @GetMapping("/status-codes-demo/{scenario}")
    public ResponseEntity<?> statusCodesDemo(
            @PathVariable String scenario,
            @RequestParam(defaultValue = "false") boolean forceError,
            HttpServletResponse response) {
        
        System.out.println("=== STATUS CODES DEMO ===");
        System.out.println("Scenario: " + scenario);
        
        return switch (scenario.toLowerCase()) {
            case "success" -> {
                response.setStatus(HttpStatus.OK.value());
                yield ResponseEntity.ok()
                    .body(Map.of("status", 200, "message", "Success response"));
            }
            case "created" -> {
                response.setStatus(HttpStatus.CREATED.value());
                yield ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of("status", 201, "message", "Resource created"));
            }
            case "accepted" -> {
                response.setStatus(HttpStatus.ACCEPTED.value());
                yield ResponseEntity.status(HttpStatus.ACCEPTED)
                    .body(Map.of("status", 202, "message", "Request accepted for processing"));
            }
            case "no-content" -> {
                response.setStatus(HttpStatus.NO_CONTENT.value());
                yield ResponseEntity.noContent().build();
            }
            case "bad-request" -> {
                response.setStatus(HttpStatus.BAD_REQUEST.value());
                yield ResponseEntity.badRequest()
                    .body(Map.of("status", 400, "error", "Bad request example"));
            }
            case "unauthorized" -> {
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                yield ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("status", 401, "error", "Unauthorized access"));
            }
            case "forbidden" -> {
                response.setStatus(HttpStatus.FORBIDDEN.value());
                yield ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("status", 403, "error", "Access forbidden"));
            }
            case "not-found" -> {
                response.setStatus(HttpStatus.NOT_FOUND.value());
                yield ResponseEntity.notFound().build();
            }
            case "conflict" -> {
                response.setStatus(HttpStatus.CONFLICT.value());
                yield ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("status", 409, "error", "Resource conflict"));
            }
            case "server-error" -> {
                response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                yield ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", 500, "error", "Internal server error"));
            }
            default -> ResponseEntity.badRequest()
                .body(Map.of(
                    "status", 400,
                    "error", "Unknown scenario: " + scenario,
                    "availableScenarios", List.of(
                        "success", "created", "accepted", "no-content",
                        "bad-request", "unauthorized", "forbidden", "not-found",
                        "conflict", "server-error"
                    )
                ));
        };
    }


```
