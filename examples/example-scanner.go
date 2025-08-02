package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Scanner struct { // This struct is used to store the Metadata of the Scanner object
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type Capability struct { //This struct is used to store the type and different MIME types formats
	Type              string   `json:"type"`
	ConsumerMIMETypes []string `json:"consumer_mime_types"`
	ProductMIMETypes  []string `json:"product_mime_types"`
}

type MetadataResponse struct {
	Scanner      Scanner           `json:"scanner"`
	Capabilities []Capability      `json:"capability"`
	Properties   map[string]string `json:"propeties"`
}

type ScanRequest struct {
}

type ScanResponse struct {
	ID string `json:"id"`
}

var scanTimeStamps = make(map[string]time.Time)

func scanHandler(w http.ResponseWriter, r *http.Request) { // After providing the metaa data, this function immeadiately
	if r.Method != http.MethodPost { // doesn't start the scanning, but takes it sends back the UUID and accepted status
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	scanID := uuid.New().String() // Generates a unique UUID for each scan request
	scanTimeStamps[scanID] = time.Now()
	log.Printf("Accepted New Scan request with ID: %s", scanID)

	response := ScanResponse{ID: scanID} // Sends back the status of accepted
	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(response)

}

func reportHandler(w http.ResponseWriter, r *http.Request) { // This function checks if client asks for report within 10 seconds if it does, then it gracefully asks to retry afetr 10 seconds
	scanID := strings.TrimPrefix(r.URL.Path, "/api/v1/scan/")
	scanID = strings.TrimSuffix(scanID, "/report")

	startTime, ok := scanTimeStamps[scanID] // Checks if the scanner ID exists
	if !ok {
		http.Error(w, "Scan Request Not Found", http.StatusNotFound)
		return
	}

	if time.Since(startTime) < 10*time.Second { // Checks if it's atleast been 10 seconds
		log.Printf("Scan Report for %s is not yet ready. Try after 10 seconds!", scanID)
		w.Header().Set("Retry-After", "10")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	log.Printf("Scan Report ready for %s. Checking Accepted Header", scanID)

	acceptHeader := r.Header.Get("Accept") // This block checks for the compatible header type
	report := getHardcodedV11Report()

	if strings.Contains(acceptHeader, "application/vnd.security.vulnerability.report; version=1.1") ||
		strings.Contains(acceptHeader, "*/*") || strings.Contains(acceptHeader, "text/html") {

		w.Header().Set("Content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(report)

	} else {
		log.Printf("Client request unsupported header request")
		w.Header().Set("Content-type", "application/json")
		w.WriteHeader(http.StatusNotAcceptable)
		w.Write([]byte(`{"error" : Unacceptable Header type. Try using curl or postman}`))
	}

}

func getHardcodedV11Report() map[string]interface{} {
	return map[string]interface{}{
		"generated at": time.Now().Format(time.RFC1123),
		"artifact": map[string]string{
			"repository": "library/photon",
			"digest":     "sha256:..",
		},
		"scanner": map[string]string{
			"name":    "Go Example scanner",
			"vendor":  "Harbor Contributor",
			"version": "v1.0.0",
		},
		"vulnerabilities": []map[string]string{
			{
				"id":          "CVE-2034-0464",
				"package":     "openssl",
				"version":     "3.0.8-r1",
				"severity":    "High",
				"description": "A vunerability in openssl",
			},
		},
	}
}

func metadataHandler(w http.ResponseWriter, r *http.Request) { // This function is used to provide the Metadata, Capabilities and Properties to the client
	metadata := MetadataResponse{
		Scanner: Scanner{
			Name:    "Hello Handler",
			Vendor:  "Harbor Contributor",
			Version: "1.0.0",
		},
		Capabilities: []Capability{
			{
				Type:              "Vulnerability",
				ConsumerMIMETypes: []string{"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"},
				ProductMIMETypes:  []string{"application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0", "application/vnd.security.vulnerability.report; version=1.1"},
			},
		},
		Properties: map[string]string{
			"harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
			"example.property/is-a-poc":           "true",
		},
	}

	w.Header().Set("Content-type", "application/vnd.scanner.adapter.metadata+json; version=1.1")

	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		log.Printf("Error while encoding the data into json")
		http.Error(w, "Error while generating metadata", http.StatusInternalServerError)
	}
}

func main() {
	http.HandleFunc("/api/v1/metadata", metadataHandler)
	http.HandleFunc("/api/v1/scan", scanHandler)
	http.HandleFunc("/api/v1/scan/", reportHandler)
	log.Println("Example Scanner listening at port 8080 :")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start the server : %s", err)
	}
}
