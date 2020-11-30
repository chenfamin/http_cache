
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


#define N 4

int nr;
int nw;

struct btree_node_t {
	off64_t offset;
	off64_t childs[2 * N];
	int keys[2 * N - 1];
	int keys_count;
	int is_leaf;
};

struct btree_t {
	int fd;
	off64_t offset;
	struct btree_node_t *btree_node;//root node
	int height;
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

void print_node(const char *mess, struct btree_node_t *btree_node)
{
	int i = 0;
	printf("%s----%lld\n", mess, btree_node->offset);
	for(i = 0; i < btree_node->keys_count; i++) {
		printf("%-3d ", btree_node->keys[i]);
	}
	printf("\n");
	for(i = 0; i < btree_node->keys_count + 1; i++) {
		printf("%-3d ", btree_node->childs[i]);
	}
	printf("\n\n");
}

struct btree_node_t *btree_node_alloc(struct btree_t *btree)
{
	struct btree_node_t *btree_node = NULL;
	btree_node = malloc(sizeof(struct btree_node_t));
	memset(btree_node, 0, sizeof(struct btree_node_t));
	btree_node->offset = btree->offset;
	btree->offset += sizeof(struct btree_node_t);
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
	btree_node_disk_write(btree, btree->btree_node);
}

struct btree_node_t *btree_search(struct btree_t *btree, struct btree_node_t *btree_node, int key)
{
	int i = 0;
	while (i < btree_node->keys_count && key > btree_node->keys[i]) {
		i++;
	}
	if (i < btree_node->keys_count && key == btree_node->keys[i]) {
		printf("find i=%d\n", i);
		return btree_node;
	}
	if (btree_node->is_leaf) {
		return NULL;
	} else {
		struct btree_node_t *btree_node_child = btree_node_disk_read(btree, btree_node->childs[i]);
		return btree_search(btree, btree_node_child, key);
	}
}

struct btree_node_t *btree_node_split(struct btree_t *btree, struct btree_node_t *btree_node_parent, int index, struct btree_node_t *btree_node_child)
{
	int i = 0;
	struct btree_node_t *btree_node_new = NULL;
	btree_node_new = btree_node_alloc(btree);
	//printf("new_offset = %lld\n", btree_node_new->offset);
	btree_node_new->is_leaf = btree_node_child->is_leaf;
	btree_node_new->keys_count = N - 1;
	for (i = 0; i < N - 1; i++) {
		btree_node_new->keys[i] = btree_node_child->keys[i + N];
	}
	if (btree_node_child->is_leaf == 0) {
		for (i = 0; i < N; i++) {
			btree_node_new->childs[i] = btree_node_child->childs[i + N];
		}
	}
	btree_node_child->keys_count = N - 1;
	for (i = btree_node_parent->keys_count - 1; i >= index; i--) {
		btree_node_parent->keys[i + 1] = btree_node_parent->keys[i];
	}
	btree_node_parent->keys[index] = btree_node_child->keys[N - 1];
	for (i = btree_node_parent->keys_count; i >= index + 1; i--) {
		btree_node_parent->childs[i + 1] = btree_node_parent->childs[i];
	}
	btree_node_parent->childs[index + 1] = btree_node_new->offset;
	btree_node_parent->keys_count++;
	btree_node_disk_write(btree, btree_node_parent);
	btree_node_disk_write(btree, btree_node_child);
	btree_node_disk_write(btree, btree_node_new);
	return btree_node_new;
}

void btree_node_insert_nonfull(struct btree_t *btree, struct btree_node_t *btree_node, int key)
{
	int i;
	struct btree_node_t *btree_node_child = NULL;
	struct btree_node_t *btree_node_new = NULL;
	i = btree_node->keys_count - 1;
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
		if (btree_node_child->keys_count == 2 * N - 1) {
			btree_node_new = btree_node_split(btree, btree_node, i, btree_node_child);
			if (key > btree_node->keys[i]) {
				i++;
				btree_node_free(btree_node_child);
				btree_node_child = btree_node_new;
			} else {
				btree_node_free(btree_node_new);
			}
		}
		btree_node_insert_nonfull(btree, btree_node_child, key);
		btree_node_free(btree_node_child);
	}
}

void btree_print(struct btree_t *btree, struct btree_node_t *btree_node)
{
	int i;
	struct btree_node_t *btree_node_next;
	if (btree->btree_node != btree_node) {
		assert(btree_node->keys_count >= N - 1);
	}
	if (btree_node->is_leaf == 0) {
		for (i = 0; i < btree_node->keys_count; i++) {
			btree_node_next = btree_node_disk_read(btree, btree_node->childs[i]);
			btree_print(btree, btree_node_next);
			printf("%-3d ", btree_node->keys[i]);
			btree_node_free(btree_node_next);
		}
		btree_node_next = btree_node_disk_read(btree, btree_node->childs[btree_node->keys_count]);
		btree_print(btree, btree_node_next);
		btree_node_free(btree_node_next);
	} else {
		for (i = 0; i < btree_node->keys_count; i++) {
			printf("%-3d ", btree_node->keys[i]);
		}
	}
}

void btree_insert(struct btree_t *btree, int key)
{
	struct btree_node_t *btree_node = btree->btree_node;
	struct btree_node_t *btree_node_root = NULL;
	struct btree_node_t *btree_node_child = NULL;
	if (btree_node->keys_count == 2 * N - 1) {
		btree_node_root = btree_node_alloc(btree);
		btree->btree_node = btree_node_root;
		btree_node_root->is_leaf = 0;
		btree_node_root->keys_count = 0;
		btree_node_root->childs[0] = btree_node->offset;
		btree_node_child = btree_node_split(btree, btree_node_root, 0, btree_node);
		btree_node_insert_nonfull(btree, btree_node_root, key);
		btree->height++;
		btree_node_free(btree_node_child);
		btree_node_free(btree_node);
	} else {
		btree_node_insert_nonfull(btree, btree_node, key);
	}
}

void btree_node_delete(struct btree_t *btree, struct btree_node_t *btree_node, int index)
{
	struct btree_node_t *btree_node_child_left = NULL;
	struct btree_node_t *btree_node_child_right = NULL;
	int i = 0;
	if (btree_node->is_leaf) {
		for (i = index; i < btree_node->keys_count - 1; i++) {
			btree_node->keys[i] = btree_node->keys[i + 1];
		}
		btree_node->keys_count--;
		btree_node_disk_write(btree, btree_node);
	} else {
		btree_node_child_left = btree_node_disk_read(btree, btree_node->childs[index]);
		if (btree_node_child_left->keys_count >= N) {
			btree_node->keys[index] = btree_node_child_left->keys[btree_node_child_left->keys_count - 1];
			btree_node_delete(btree, btree_node_child_left, btree_node_child_left->keys_count - 1);
			btree_node_disk_write(btree, btree_node);
		} else {
			btree_node_child_right = btree_node_disk_read(btree, btree_node->childs[index + 1]);
			if (btree_node_child_right->keys_count >= N) {
				btree_node->keys[index] = btree_node_child_right->keys[0];
				btree_node_delete(btree, btree_node_child_right, 0);
				btree_node_disk_write(btree, btree_node);
			} else {
				assert(btree_node_child_left->keys_count == N -1 && btree_node_child_right->keys_count == N -1);
				for (i = index; i < btree_node->keys_count - 1; i++) {
					btree_node->keys[i] = btree_node->keys[i + 1];
				}
				for (i = index + 1; i < btree_node->keys_count; i++) {
					btree_node->childs[i] = btree_node->childs[i + 1];
				}
				btree_node->keys_count--;
				btree_node_disk_write(btree, btree_node);
				btree_node_child_left->keys[N - 1] = btree_node->keys[index];
				for (i = 0; i < btree_node_child_right->keys_count; i++) {
					btree_node_child_left->keys[N + i] = btree_node_child_right->keys[i];
				}
				for (i = 0; i < btree_node_child_right->keys_count + 1; i++) {
					btree_node_child_left->childs[N + i] = btree_node_child_right->childs[i];
				}
				btree_node_child_left->keys_count += btree_node_child_right->keys_count;
				btree_node_disk_free(btree, btree_node_child_right->offset);
				btree_node_disk_write(btree, btree_node_child_left);
				btree_node_delete(btree, btree_node_child_left, N - 1);
			}
			btree_node_free(btree_node_child_right);
		}
		btree_node_free(btree_node_child_left);
	}
}

void btree_node_borrow_left(struct btree_t *btree, struct btree_node_t *btree_node_parent, int index, struct btree_node_t *btree_node, struct btree_node_t *btree_node_left)
{
	//printf("%s\n", __FUNCTION__);
	int i = 0;
	for (i = btree_node->keys_count - 1; i >= 0; i--) {
		btree_node->keys[i + 1] = btree_node->keys[i];
	}
	for (i = btree_node->keys_count; i >= 0; i--) {
		btree_node->childs[i + 1] = btree_node->childs[i];
	}
	btree_node->keys[0] = btree_node_parent->keys[index];
	btree_node->childs[0] = btree_node_left->childs[btree_node_left->keys_count];
	btree_node->keys_count++;
	btree_node_parent->keys[index] = btree_node_left->keys[btree_node_left->keys_count - 1];
	btree_node_left->keys_count--;
	btree_node_disk_write(btree, btree_node_parent);
	btree_node_disk_write(btree, btree_node);
	btree_node_disk_write(btree, btree_node_left);
}

void btree_node_borrow_right(struct btree_t *btree, struct btree_node_t *btree_node_parent, int index, struct btree_node_t *btree_node, struct btree_node_t *btree_node_right)
{
	//printf("%s\n", __FUNCTION__);
	int i = 0;
	btree_node->keys[btree_node->keys_count] = btree_node_parent->keys[index];
	btree_node->childs[btree_node->keys_count + 1] = btree_node_right->childs[0];
	btree_node->keys_count++;
	btree_node_parent->keys[index] = btree_node_right->keys[0];
	for (i = 0; i < btree_node_right->keys_count - 1; i++) {
		btree_node_right->keys[i] = btree_node_right->keys[i + 1];
	}
	for (i = 0; i < btree_node_right->keys_count; i++) {
		btree_node_right->childs[i] = btree_node_right->childs[i + 1];
	}
	btree_node_right->keys_count--;
	btree_node_disk_write(btree, btree_node_parent);
	btree_node_disk_write(btree, btree_node);
	btree_node_disk_write(btree, btree_node_right);
}


void btree_node_merge(struct btree_t *btree, struct btree_node_t *btree_node_parent, int index, struct btree_node_t *btree_node_left, struct btree_node_t *btree_node_right)
{
	//printf("%s\n", __FUNCTION__);
	int i = 0;
	btree_node_left->keys[btree_node_left->keys_count] = btree_node_parent->keys[index];
	for (i = 0; i < btree_node_right->keys_count; i++) {
		btree_node_left->keys[i + btree_node_left->keys_count + 1] = btree_node_right->keys[i];
	}
	for (i = 0; i < btree_node_right->keys_count + 1; i++) {
		btree_node_left->childs[i + btree_node_left->keys_count + 1] = btree_node_right->childs[i];
	}
	btree_node_left->keys_count += btree_node_right->keys_count + 1;
	for (i = index; i < btree_node_parent->keys_count; i++) {
		btree_node_parent->keys[i] = btree_node_parent->keys[i + 1];
	}
	for (i = index + 1; i < btree_node_parent->keys_count + 1; i++) {
		btree_node_parent->childs[i] = btree_node_parent->childs[i + 1];
	}
	btree_node_parent->keys_count--;
	btree_node_disk_write(btree, btree_node_parent);
	btree_node_disk_write(btree, btree_node_left);
	btree_node_disk_free(btree, btree_node_right->offset);
}

int btree_node_search_delete(struct btree_t *btree, struct btree_node_t *btree_node, int key)
{
	int i = 0;
	int ret = 0;
	struct btree_node_t *btree_node_child = NULL;
	struct btree_node_t *btree_node_child_left = NULL;
	struct btree_node_t *btree_node_child_right = NULL;
	while (i < btree_node->keys_count && key > btree_node->keys[i]) {
		i++;
	}

	if (i < btree_node->keys_count && key == btree_node->keys[i]) {
		btree_node_delete(btree, btree_node, i);
		return 0;
	} else if (btree_node->is_leaf) {
		return -1;
	}

	btree_node_child = btree_node_disk_read(btree, btree_node->childs[i]);
	if (btree_node_child->keys_count >= N) {
		ret = btree_node_search_delete(btree, btree_node_child, key);
		goto finish;
	}
	assert(btree_node_child->keys_count == N - 1);
	if (i - 1 >= 0) {
		btree_node_child_left = btree_node_disk_read(btree, btree_node->childs[i - 1]);
		if (btree_node_child_left->keys_count >= N) {
			btree_node_borrow_left(btree, btree_node, i - 1, btree_node_child, btree_node_child_left);
			ret = btree_node_search_delete(btree, btree_node_child, key);
			goto finish;
		}
	}
	if (i + 1 <= btree_node->keys_count) {
		btree_node_child_right = btree_node_disk_read(btree, btree_node->childs[i + 1]);
		if (btree_node_child_right->keys_count >= N) {
			btree_node_borrow_right(btree, btree_node, i, btree_node_child, btree_node_child_right);
			ret = btree_node_search_delete(btree, btree_node_child, key);
			goto finish;
		}
	}
	if (btree_node_child_left) {
		assert(btree_node_child_left->keys_count == N - 1);
		btree_node_merge(btree, btree_node, i - 1, btree_node_child_left, btree_node_child);
		ret = btree_node_search_delete(btree, btree_node_child_left, key);
	} else if (btree_node_child_right) {
		assert(btree_node_child_right->keys_count == N - 1);
		btree_node_merge(btree, btree_node, i, btree_node_child, btree_node_child_right);
		ret = btree_node_search_delete(btree, btree_node_child, key);
	}
finish:
	if (btree_node_child) {
		btree_node_free(btree_node_child);
	}
	if (btree_node_child_left) {
		btree_node_free(btree_node_child_left);
	}
	if (btree_node_child_right) {
		btree_node_free(btree_node_child_right);
	}
	return ret;
}

int btree_delete(struct btree_t *btree, int key)
{
	int ret = 0;
	struct btree_node_t *btree_node = btree->btree_node;
	off64_t child = btree_node->childs[0]; 	
	ret = btree_node_search_delete(btree, btree_node, key);
	if (btree_node->keys_count == 0) {
		printf("root\n");
		btree_node_disk_free(btree, btree_node->offset);
		btree_node_free(btree_node);
		btree->height--;
		btree->btree_node = btree_node_disk_read(btree, child);
	}
	return ret;
}

/*

int main()
{
	int i = 0;
	struct btree_t btree;
	btree_init(&btree);
	srandom(time(NULL));
	for (i = 0; i < 1000; i++) {
		btree_insert(&btree, i);
	}
	printf("height=%d\n", btree.height);
	printf("read=%d write=%d\n", nr, nw);
	nr = 0; nw = 0;
	//btree_search(&btree, btree.btree_node, 80);
	for (i = 0; i < 1000; i++) {
	//	printf("i=%d ret=%d\n", i, btree_delete(&btree, i));
		assert(btree_delete(&btree, i) == 0);
	}
	printf("read=%d write=%d\n", nr, nw);
//	btree_print(&btree, btree.btree_node);
	printf("\n");
	printf("height=%d\n", btree.height);
	close(btree.fd);
	btree_node_free(btree.btree_node);
	return 0;
}

*/
