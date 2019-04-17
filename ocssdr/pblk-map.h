/*
 * RB operations are not in need and deprecated
 */


#include "pblk.h"

// RB tree func cores
static struct group_l2p_node *group_l2p_rb_search(struct rb_root *root, u64 lba)
{
	struct rb_node *node = root->rb_node;
	struct group_l2p_node *l2p_data;
	while (node) {
		l2p_data = container_of(node, struct group_l2p_node, node);
		if (lba > l2p_data->lba) 
			node = node->rb_right;
		else if (lba < l2p_data->lba)
			node = node->rb_left;
		else
			return l2p_data;
	}
	return NULL;
}

static int group_l2p_rb_insert(struct rb_root *root, struct group_l2p_node *data) 
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct group_l2p_node *this;
	while (*new) {
		this = container_of(*new, struct group_l2p_node, node);
		parent = *new;
		if (data->lba < this->lba)
			new = &((*new)->rb_left);
		else if(data->lba > this->lba)
			new = &((*new)->rb_right);
		else
			return 0; // fail: exists
	}

	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);
	return 1;
}

static int group_l2p_rb_clean(struct pblk_md_line_group_set *set)
{
	struct rb_root *root = &set->l2p_rb_root;
	struct rb_node *node;
	struct group_l2p_node **nodes = set->nodes_buffer;
	int cur = 0;
	int i;

	for (node = rb_first(root); node; node = rb_next(node)) {
		if (cur >= set->nodes_buffer_size)
			return 0;
		nodes[cur] = container_of(node, struct group_l2p_node, node);
		cur ++;
	}

	if (cur != set->rb_size)
		return 0;

	for (i = 0; i < cur; i++)
		kfree(nodes[i]);
	return 1;
}
