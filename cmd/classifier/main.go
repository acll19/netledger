package main

import "fmt"

func main() {
	fmt.Println("Classifier")
	// TODO
	// agent will send pod namespace and name
	// if pod not found assign "unknown"
	// should keep map of active active pod (pod IP to pod metadata)
	// when informed that pod was deleted, move to tombstone cache for 120 seconds...
	// ...before deleting for ever
	// should classify traffic
	// should emit Prometheus metric
}
