
#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <assert.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>


#define MAX_DEGREE 5

#define max_key_count (MAX_DEGREE - 1)
#define min_key_count ((MAX_DEGREE + 1) / 2 - 1)

int nr;
int nw;

struct btree_node_t {
	off64_t offset;
	off64_t next;
	int is_leaf;
	off64_t childs[max_key_count + 2];
	int keys[max_key_count + 1];
	int keys_count;
};

struct btree_t {
	int fd;
	off64_t offset;
	struct btree_node_t *btree_node;//root node
	int height;

	int smallest;
	int smallest_index;
};

int btree_node_disk_write(struct btree_t *btree, struct btree_node_t *btree_node)
{
	off64_t offset = 0;
	ssize_t nwrite = 0;
	offset = lseek64(btree->fd, btree_node->offset, SEEK_SET);
	assert(offset == btree_node->offset);
	nwrite = write(btree->fd, btree_node, sizeof(struct btree_node_t));
	assert(nwrite == sizeof(struct btree_node_t));

	nw++;
	return 0;
}

struct btree_node_t *btree_node_disk_read(struct btree_t *btree, off64_t off)
{
	off64_t offset = 0;
	ssize_t nread = 0;
	struct btree_node_t *btree_node = NULL;
	btree_node = malloc(sizeof(struct btree_node_t));
	memset(btree_node, 0, sizeof(struct btree_node_t));
	offset = lseek64(btree->fd, off, SEEK_SET);
	assert(offset == off);
	nread = read(btree->fd, btree_node, sizeof(struct btree_node_t));
	assert(nread == sizeof(struct btree_node_t));
	nr++;
	return btree_node;
}

void btree_node_disk_free(struct btree_t *btree, off64_t off)
{
}

struct btree_node_t *btree_node_alloc(struct btree_t *btree)
{
	struct btree_node_t *btree_node = NULL;
	btree_node = malloc(sizeof(struct btree_node_t));
	memset(btree_node, 0, sizeof(struct btree_node_t));
	btree_node->offset = btree->offset;
	btree->offset += sizeof(struct btree_node_t);
	btree_node->next = -1;
	return btree_node;
}

void btree_node_free(struct btree_node_t *btree_node)
{
	free(btree_node);
}

void btree_init(struct btree_t *btree)
{
	memset(btree, 0, sizeof(struct btree_t));
	btree->fd = open("data", O_RDWR|O_CREAT|O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
	assert(btree->fd > 0);
	btree->offset = 0;
	btree->btree_node = btree_node_alloc(btree);
	btree->btree_node->keys_count = 0;
	btree->btree_node->is_leaf = 1;
	btree->btree_node->next = -1;
	btree_node_disk_write(btree, btree->btree_node);
}

void btree_print_node(struct btree_t *btree, off64_t next, int depth)
{
	int i = 0;
	struct btree_node_t *btree_node = NULL;
	printf("depth[%d]-> ", depth);
	while (next >= 0) {
		btree_node = btree_node_disk_read(btree, next);
		for (i = 0; i < btree_node->keys_count; i++) {
			printf("%-3d ", btree_node->keys[i]);
		}
		printf("   |    ");
		next = btree_node->next;
		btree_node_free(btree_node);
	}
	printf("\n");
}


void btree_print(struct btree_t *btree)
{
	int i = 0;
	int is_leaf = 0;
	off64_t child = btree->btree_node->offset;
	struct btree_node_t *btree_node = NULL;
	while (child >= 0) {
		btree_node = btree_node_disk_read(btree, child);
		btree_print_node(btree, child, i);
		child = btree_node->childs[0];
		is_leaf = btree_node->is_leaf;
		btree_node_free(btree_node);
		i++;
		if (is_leaf) {
			break;
		}
	}
}

struct btree_node_t *btree_node_split(struct btree_t *btree, struct btree_node_t *btree_node_parent, int index, struct btree_node_t *btree_node_child)
{
	int i = 0;
	struct btree_node_t *btree_node_new = NULL;
	int keys_count = btree_node_child->keys_count;
	btree_node_new = btree_node_alloc(btree);
	btree_node_new->is_leaf = btree_node_child->is_leaf;
	if (btree_node_new->is_leaf) {
		btree_node_child->keys_count = keys_count / 2;
		btree_node_new->keys_count = keys_count - btree_node_child->keys_count;
	} else {
		btree_node_child->keys_count = keys_count / 2;
		btree_node_new->keys_count = keys_count - btree_node_child->keys_count - 1;
		memcpy(btree_node_new->childs, btree_node_child->childs + btree_node_child->keys_count + 1,
				(btree_node_new->keys_count + 1) * sizeof(off64_t));
	}
	memcpy(btree_node_new->keys, btree_node_child->keys + (keys_count - btree_node_new->keys_count), btree_node_new->keys_count * sizeof(int));
	memmove(btree_node_parent->keys + index + 1, btree_node_parent->keys + index, (btree_node_parent->keys_count - index) * sizeof(int));

	memmove(btree_node_parent->childs + index + 2, btree_node_parent->childs + index + 1, (btree_node_parent->keys_count - index) * sizeof(off64_t));
	btree_node_parent->keys[index] = btree_node_child->keys[btree_node_child->keys_count];
	btree_node_parent->childs[index + 1] = btree_node_new->offset;
	btree_node_parent->keys_count++;
	btree_node_new->next = btree_node_child->next;
	btree_node_child->next = btree_node_new->offset;
	btree_node_disk_write(btree, btree_node_child);
	btree_node_disk_write(btree, btree_node_new);
	btree_node_disk_write(btree, btree_node_parent);
	btree_node_free(btree_node_new);
	return NULL;
}

void btree_node_insert_nonfull(struct btree_t *btree, struct btree_node_t *btree_node, int key)
{
	struct btree_node_t *btree_node_child = NULL;
	int i = btree_node->keys_count - 1;
	if (btree_node->is_leaf) {
		while (i >= 0 && key < btree_node->keys[i]) {
			btree_node->keys[i+1] = btree_node->keys[i];
			i--;
		}
		btree_node->keys[i+1] = key;
		btree_node->keys_count++;
		btree_node_disk_write(btree, btree_node);
	} else {
		while (i >= 0 && key < btree_node->keys[i]) {
			i--;
		}
		i++;
		btree_node_child = btree_node_disk_read(btree, btree_node->childs[i]);
		btree_node_insert_nonfull(btree, btree_node_child, key);
		if (btree_node_child->keys_count > max_key_count) {
			btree_node_split(btree, btree_node, i, btree_node_child);
		}
	}
	btree_node_free(btree_node_child);
}

void btree_insert(struct btree_t *btree, int key)
{
	struct btree_node_t *btree_node_root = NULL;
	struct btree_node_t *btree_node = btree->btree_node;
	btree_node_insert_nonfull(btree, btree_node, key);
	if (btree_node->keys_count > max_key_count) {
		btree_node_root = btree_node_alloc(btree);
		btree->btree_node = btree_node_root;
		btree_node_root->is_leaf = 0;
		btree_node_root->keys_count = 0;
		btree->height++;
		btree_node_root->childs[0] = btree_node->offset;
		btree_node_split(btree, btree_node_root, 0, btree_node);
		btree_node_free(btree_node);
	}
}

void btree_node_borrow_left(struct btree_t *btree, struct btree_node_t *btree_node_parent, int index, struct btree_node_t *btree_node, struct btree_node_t *btree_node_left)
{
	memmove(btree_node->keys + 1, btree_node->keys, btree_node->keys_count * sizeof(int));
	if (btree_node->is_leaf) {
		btree_node->keys[0] = btree_node_left->keys[btree_node_left->keys_count - 1];
		btree_node_parent->keys[index] = btree_node->keys[0];
	} else {
		memmove(btree_node->childs + 1, btree_node->childs, (btree_node->keys_count + 1)  * sizeof(off64_t));
		btree_node->keys[0] = btree_node_parent->keys[index];
		btree_node->childs[0] = btree_node_left->childs[btree_node_left->keys_count];
		btree_node_parent->keys[index] = btree_node_left->keys[btree_node_left->keys_count - 1];
	}
	btree_node->keys_count++;
	btree_node_left->keys_count--;
	btree_node_disk_write(btree, btree_node_parent);
	btree_node_disk_write(btree, btree_node);
	btree_node_disk_write(btree, btree_node_left);
}

void btree_node_borrow_right(struct btree_t *btree, struct btree_node_t *btree_node_parent, int index, struct btree_node_t *btree_node, struct btree_node_t *btree_node_right)
{
	btree_node->keys[btree_node->keys_count] = btree_node_parent->keys[index];
	if (btree_node->is_leaf) {
		memmove(btree_node_right->keys, btree_node_right->keys + 1, (btree_node_right->keys_count - 1) * sizeof(int));
		btree_node_parent->keys[index] = btree_node_right->keys[0];
	} else {
		btree_node->childs[btree_node->keys_count + 1] = btree_node_right->childs[0];
		btree_node_parent->keys[index] = btree_node_right->keys[0];
		memmove(btree_node_right->keys, btree_node_right->keys + 1, (btree_node_right->keys_count - 1) * sizeof(int));
		memmove(btree_node_right->childs, btree_node_right->childs + 1, btree_node_right->keys_count * sizeof(off64_t));
	}
	btree_node_right->keys_count--;
	btree_node->keys_count++;
	btree_node_disk_write(btree, btree_node_parent);
	btree_node_disk_write(btree, btree_node);
	btree_node_disk_write(btree, btree_node_right);
}

void btree_node_merge(struct btree_t *btree, struct btree_node_t *btree_node_parent, int index, struct btree_node_t *btree_node_left, struct btree_node_t *btree_node_right)
{
	int i = 0;
	if (btree_node_left->is_leaf) {
		memcpy(btree_node_left->keys + btree_node_left->keys_count, btree_node_right->keys, btree_node_right->keys_count * sizeof(int));
		btree_node_left->keys_count += btree_node_right->keys_count;
	} else {
		btree_node_left->keys[btree_node_left->keys_count] = btree_node_parent->keys[index];
		memcpy(btree_node_left->keys + 1 + btree_node_left->keys_count, btree_node_right->keys, btree_node_right->keys_count * sizeof(int));
		memcpy(btree_node_left->childs + btree_node_left->keys_count + 1, btree_node_right->childs, (btree_node_right->keys_count + 1) * sizeof(off64_t));
		btree_node_left->keys_count += btree_node_right->keys_count + 1;
	}
	memmove(btree_node_parent->keys + index, btree_node_parent->keys + index + 1, (btree_node_parent->keys_count - index - 1) * sizeof(int));
	memmove(btree_node_parent->childs + index + 1, btree_node_parent->childs + index + 2, (btree_node_parent->keys_count - index) * sizeof(off64_t));
	btree_node_left->next = btree_node_right->next;
	btree_node_parent->keys_count--;
	btree_node_disk_write(btree, btree_node_parent);
	btree_node_disk_write(btree, btree_node_left);
	btree_node_disk_free(btree, btree_node_right->offset);
}

void print_node(struct btree_node_t *btree_node)
{
	int i = 0;
	printf("print_node ");
	for (i = 0; i < btree_node->keys_count; i++) {
		printf("%-3d ", btree_node->keys[i]);
	}
	printf("\n");
}

int btree_node_search_delete(struct btree_t *btree, struct btree_node_t *btree_node, int key)
{
	int index = 0;
	int i = 0;
	struct btree_node_t *btree_node_child = NULL;
	struct btree_node_t *btree_node_child_left = NULL;
	struct btree_node_t *btree_node_child_right = NULL;

	struct btree_node_t *btree_node_current = NULL;
	if (btree_node->is_leaf) {
		while (i < btree_node->keys_count && key > btree_node->keys[i]) {
			i++;
		}
		if (i < btree_node->keys_count && key == btree_node->keys[i]) {
			memmove(btree_node->keys + i, btree_node->keys + i + 1, (btree_node->keys_count - i - 1) * sizeof(int));
			btree_node->keys_count--;
			btree_node_disk_write(btree, btree_node);
			return i;
		} else {
			printf("cannot find key=%d\n", key);
			return -1;
		}
	}
	while (i < btree_node->keys_count && key >= btree_node->keys[i]) {
		i++;
	}
	btree_node_child = btree_node_disk_read(btree, btree_node->childs[i]);
	btree_node_current = btree_node_child;
	index = btree_node_search_delete(btree, btree_node_child, key);
	if (index < 0) {
		i = -1;
		goto finish;
	}

	if (btree_node_child->keys_count >= min_key_count) {
		goto finish;
	}

	if (i - 1 >= 0) {
		btree_node_child_left = btree_node_disk_read(btree, btree_node->childs[i - 1]);
		if (btree_node_child_left->keys_count > min_key_count) {
			btree_node_borrow_left(btree, btree_node, i - 1, btree_node_child, btree_node_child_left);
			index++;
			goto finish;
		}
	}

	if (i + 1 <= btree_node->keys_count) {
		btree_node_child_right = btree_node_disk_read(btree, btree_node->childs[i + 1]);
		if (btree_node_child_right->keys_count > min_key_count) {
			btree_node_borrow_right(btree, btree_node, i, btree_node_child, btree_node_child_right);
			goto finish;
		}
	}

	if (btree_node_child_left) {
		if (btree_node_child->is_leaf) {
			index += btree_node_child_left->keys_count;
		} else {
			index += btree_node_child_left->keys_count + 1;
		}
		btree_node_current = btree_node_child_left;
		btree_node_merge(btree, btree_node, i - 1, btree_node_child_left, btree_node_child);
		i--;
	} else if (btree_node_child_right) {
		btree_node_merge(btree, btree_node, i, btree_node_child, btree_node_child_right);
	}

finish:
	if (index == 0) {
		if (btree_node_current->is_leaf) {
			btree->smallest_index = 0;
			btree->smallest = btree_node_current->keys[0];
		}
	} else if (index > 0) {
		if (btree->smallest_index == 0) {
			btree_node_current->keys[index - 1] = btree->smallest;
			btree->smallest_index = -1;
			btree_node_disk_write(btree, btree_node_current);
		}
	}

	btree_node_free(btree_node_child);
	if (btree_node_child_left) {
		btree_node_free(btree_node_child_left);
	}
	if (btree_node_child_right) {
		btree_node_free(btree_node_child_right);
	}
	return i;
}

int btree_delete(struct btree_t *btree, int key)
{
	int index = 0;
	struct btree_node_t *btree_node = btree->btree_node;
	off64_t child = btree_node->childs[0]; 	
	btree->smallest_index = -1;
	index = btree_node_search_delete(btree, btree_node, key);
	if (index >= 0) {
		if (index > 0 && btree->smallest_index == 0) {
			btree_node->keys[index - 1] = btree->smallest;
			btree->smallest_index = -1;
			btree_node_disk_write(btree, btree_node);
		}
		if (btree_node->keys_count == 0) {
			btree_node_disk_free(btree, btree_node->offset);
			btree_node_free(btree_node);
			btree->height--;
			btree->btree_node = btree_node_disk_read(btree, child);
		}
	} else {
		assert(0);
	}
	return index;
}

int main()
{
	int i = 0;
	struct btree_t btree;
	btree_init(&btree);
	srandom(time(NULL));
	printf("min_key_count=%d max_key_cout=%d\n", min_key_count, max_key_count);
	for (i = 0; i < 22; i++) {
		btree_insert(&btree, i);
	}
	btree_print(&btree);
	for (i = 0; i < 22; i++) {
		printf("delete %d\n", i);
		btree_delete(&btree, i);
		btree_print(&btree);
	}
	printf("height=%d\n", btree.height);
	printf("read=%d write=%d\n", nr, nw);
	printf("\n");
	close(btree.fd);
	btree_node_free(btree.btree_node);
	return 0;
}
