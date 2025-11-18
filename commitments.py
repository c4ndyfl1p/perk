from typing import Tuple, List

LAMBDA= 12

def create_empty_ggm_tree(depth: int) -> list[list[  bytes]]:
    """Create an empty GGM tree as a list of levels.
    # a GGM tree will look like a nested list with placeholder value as b'0' which can later be filled with data
        # [
        #   [b'0],                     # level 0 (root)
        #   [b'0', b'0'],               # level 1
        #   [b'0', b'0', b'0', b'0']    # level 2
        # ]            
    
    """

    if depth < 0:
        raise ValueError("Depth must be non-negative")
    tree: list[list[ bytes]] = []
    for level in range(depth + 1):
        level_nodes: list[ bytes] = []
        for _ in range(2 ** level):
            level_nodes.append(b'0')  # Initialize with placeholder bytes
        tree.append(level_nodes)
    print(f"FUNC: create_empty_ggm_tree: Created GGM tree with depth {depth}: {tree}")
    return tree


def create_leaves(depth: int) -> Tuple[List[ bytes], List[ bytes]]:
    """creates 2 lists, each of side 2**N. one to hold each of the seeds sd_j and another to hold the hashes of them

    Args:
        depth (int): depth of hte tree

    Returns:
        Tuple[List[None], List[None]]: _description_
    """
    n = 2 ** depth
    seeds: list[ bytes] = [b'0'] * n
    commits:list[ bytes] = [b'0'] * n
    return seeds, commits

# tree = create_empty_ggm_tree(depth=3)
# tree[0][0] = "dhajkshdjs"
# # print(tree)

def PRG(j: bytes, iv: bytes, output_length: int) -> Tuple[bytes, bytes]:

    
    k_1 = b'k' * 128
    k_2 = b'k' * 128

    return k_1, k_2
    

def H_0(k_j_j:bytes, iv:bytes) -> tuple[bytes, bytes]:
    sd_j = b's' * 128
    com_j = b'c' * 128
    return sd_j, com_j

def H_1(commits:List[bytes]) -> bytes:
    h = b'h' * 128
    return h

#========

def commit(r:bytes, iv:bytes, depth:int) -> Tuple[bytes, Tuple[list[bytes], list[bytes]]]:
    
    ggm_tree_keys = create_empty_ggm_tree(depth)
    seeds ,commitments = create_leaves(depth) # leaves to hold sd_j and their hashes/decommitments
    print(f"FUNC: commit: Initialised seeds (list[None] of size {len(seeds)}):  {seeds} \n and commitments (list of size {len(commitments)}) {commitments}")
    N = 2**depth

    ggm_tree_keys[0][0] = r # type: ignore #k^0_0 = r

    # loop to fill in the GGM tree
    for i in range(1,depth+1):
        for j in range(0, 2**(i-1)):
            ggm_tree_keys[i][2*j] , ggm_tree_keys[i][(2*j) + 1]= PRG(ggm_tree_keys[i-1][j], iv, 2*LAMBDA)

    #loop to fill in the exrta layer of leaves= decommitments = seeds, commitments
    for j in range(0, N):
        seeds[j], commitments[j] = H_0(ggm_tree_keys[depth][j], iv)
        
    h = H_1(commitments)

    decommitments = (seeds, commitments)

    return h, decommitments



r = b'r' * 128
iv = b'i' * 128
depth = 3
print("Running commitments test...")
h, decommitments = commit(r, iv, depth)
print("=== Commitments Test ===")
print(f"Commitment: {h}")
print(f"Decommitments: {len(decommitments)}, {len(decommitments[0])}, {len(decommitments[1])}")
