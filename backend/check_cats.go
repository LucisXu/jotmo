// +build ignore

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Category struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	ParentID int    `json:"parent_id"`
}

type Data struct {
	Categories []Category `json:"categories"`
}

func main() {
	f, _ := os.Open("jotmo_data.json")
	defer f.Close()

	var data Data
	json.NewDecoder(f).Decode(&data)

	// Count categories by level
	l2Count := 0
	l1Count := 0
	for _, c := range data.Categories {
		if c.ParentID == -1 {
			l2Count++
		} else {
			l1Count++
		}
	}

	fmt.Printf("Total categories: %d\n", len(data.Categories))
	fmt.Printf("Level-2 (parent) categories: %d\n", l2Count)
	fmt.Printf("Level-1 categories: %d\n", l1Count)
	fmt.Println()

	// Show level-2 categories with subcategory counts
	fmt.Println("Level-2 categories:")
	for _, c := range data.Categories {
		if c.ParentID != -1 {
			continue
		}
		subCount := 0
		for _, sub := range data.Categories {
			if sub.ParentID == c.ID {
				subCount++
			}
		}
		fmt.Printf("  %s: %d subcategories\n", c.Name, subCount)
	}
}
