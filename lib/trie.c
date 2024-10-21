#include <stdbool.h>
#include "../include/lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "netinet/in.h"
#include "../include/trie.h"

TrieNode *createTrieNode(struct route_table_entry *entry) {
    TrieNode *node = calloc(1,sizeof(TrieNode));
    node->entry = entry;
    return node;
}

void addNode(TrieNode *trie, struct route_table_entry *entry){
    u_int32_t mask = ntohl(entry->mask);
    for(int i = 31; i >= 0; i--){
        if (mask == 0) {
            break;
        }
        int bit = (ntohl(entry->prefix) >> i) & 1;
        if(bit == 0){
            if(trie->left == NULL){
                trie->left = createTrieNode(NULL);
            }
            trie = trie->left;
        } else {
            if(trie->right == NULL){
                trie->right = createTrieNode(NULL);
            }
            trie = trie->right;
        }
        mask = mask << 1;
    }
    trie->entry = entry;
}

TrieNode *createTrie(struct route_table_entry *rtable, int size){
    TrieNode *trie = createTrieNode(NULL);
    for(int i = 0; i < size; i++){
        addNode(trie, &rtable[i]);
    }
    return trie;
}

struct route_table_entry *get_best_route(uint32_t ip_dest, TrieNode *trie) {
    struct route_table_entry *best_route = NULL;
    TrieNode *current_node = trie;

    for (int i = 31; i >= 0; i--) {
        int bit = (ntohl(ip_dest) >> i) & 1;
        if (bit == 0) {
            if (current_node->left != NULL){
                current_node = current_node->left;
            } else {
                break;
            }
        } else {
            if (current_node->right != NULL) {
                current_node = current_node->right;
            } else {
                break;
            }
        }
        if (current_node->entry != NULL) {
            best_route = current_node->entry;
        }
    }

    return best_route;
}

void freeTrie(TrieNode *trie){
    if(trie == NULL){
        return;
    }
    freeTrie(trie->left);
    freeTrie(trie->right);
    free(trie);
}

void printTree(struct TrieNode* root, int level) {
    if (root == NULL)
        return;
    
    // Print the current level and value
    printf("Level %d: ", level);
    printf("%d ", root->entry->mask);
    printf("\n");
    
    // Recursively print the left and right subtrees
    printTree(root->left, level + 1);
    printTree(root->right, level + 1);
}





