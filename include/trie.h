#ifndef _TRIE_H_
#define _TRIE_H_

typedef struct TrieNode {
    struct TrieNode *left;
    struct TrieNode *right;
    struct route_table_entry *entry;
} TrieNode;

TrieNode *createTrieNode(struct route_table_entry *entry);
void addNode(TrieNode *trie, struct route_table_entry *entry);
TrieNode *createTrie(struct route_table_entry *rtable, int size);
struct route_table_entry *get_best_route(uint32_t ip_dest, TrieNode *trie);
void printTree(struct TrieNode* root, int level);


#endif