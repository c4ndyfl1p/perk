from typing import Tuple, List, Literal
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import SHAKE128
from Crypto.Random import get_random_bytes
from dataclasses import dataclass
from pprint import pprint

SECLambda = Literal[128, 192, 256]

@dataclass
class ggmTreeLeaves:
    seeds : List[bytes]
    commitments : List[bytes]

@dataclass
class Decommitment:
    nodes: list[list[bytes]] #ggm tree nodes
    commitments: list[bytes]

def print_nested(lst, indent=0):
    '''Helper function to print nested lists nicely'''
    for item in lst:
        if isinstance(item, list):
            print("  " * indent + "[")
            print_nested(item, indent + 1)
            print("  " * indent + "]")
        else:
            print("  " * indent + str(item))


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


def create_leaves(depth: int) -> ggmTreeLeaves:
    """creates 2 lists, each of side 2**N. one to hold each of the seeds sd_j and another to hold the hashes of them

    Args:
        depth (int): depth of hte tree

    Returns:
        Tuple[List[None], List[None]]: _description_
    """
    n = 2 ** depth
    leaves = ggmTreeLeaves( seeds= [b'0'] * n , commitments= [b'0'] * n )
    return leaves
    # seeds: list[ bytes] = [b'0'] * n
    # commits:list[ bytes] = [b'0'] * n
    # return seeds, commits



# tree = create_empty_ggm_tree(depth=3)
# tree[0][0] = "dhajkshdjs"
# # print(tree)

def PRG(seed: bytes, iv: bytes, output_lambda: SECLambda) -> Tuple[bytes, bytes]:
    """PRG : {0, 1}λ × {0, 1}128 → {0, 1}∗, a pseudo-random generator taking as 
    input a λ-bit seed and a 128-bit initialization vector.

    We instantiate PRG(s, iv) using AES-λ in CTR mode with seed s and initialization vector iv.
    To make the output length explicit, we write PRG(s, iv; l) to indicate that ` output bits are 
    required using the seed s. If ` is not a multiple of 128, we compute d`/128e 128-bit blocks 
    of output and truncate the final block to ` mod 128 bits.

    Args:
        seed (bytes): seed is the key, with which we initialize AES-lambda. It can be 128, 192 or 256 bits long
        iv (bytes): Counter The counter is a 128-bit, big-endian integer
         initially set to iv and incremented by one after each block
        output_length (int): _description_

    Returns:
        Tuple[bytes, bytes]: _description_
    """
    if output_lambda == 128:
        if len(iv) != 128//8 :
            raise ValueError("For lambda = 128, IV must be 128 bits long")
        if len(seed) != 128//8 :
            raise ValueError("For lambda = 128, seed must be 128 bits long")

        
        
        
        key = seed # should be 128, 192 or 256 bits long
        ctr1 = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
        cipher1 = AES.new(key, AES.MODE_CTR, counter=ctr1)
        ctr2= Counter.new(128, initial_value=(int.from_bytes(iv, 'big') +1))
        cipher2 = AES.new(key, AES.MODE_CTR, counter=ctr2)

        ct1 = cipher1.encrypt(plaintext= b'\x00'*16)
        ct2 = cipher2.encrypt(plaintext= b'\x00'*16)

        k_1 = ct1
        k_2 = ct2

        return k_1, k_2
    else:
        raise NotImplementedError("PRG currently implemented only for output_lambda = 128")
    

def H_0(k_j_j:bytes, iv:bytes, output_lambda:SECLambda) -> tuple[bytes, bytes]:
    """H0 : {0, 1}^(λ+128) → {0, 1}λ * {0, 1}2λ, hash function for commitments_

    Args:
        k_j_j (bytes): _description_
        iv (bytes): _description_

    Returns:
        tuple[bytes, bytes]: _description_
    """
    #concatenate k_j_j and iv

    if len(k_j_j) != 16:
        raise ValueError("k_j_j must be 128 bits long")
    if len(iv) != 16:
        raise ValueError("iv must be 128 bits long")
    

    shake  = SHAKE128.new()
    m = k_j_j + iv 
    i = (0).to_bytes(1, 'big')
    shake.update(m + i)
    
    hash = shake.read( (output_lambda+ (2*output_lambda))//8)
    
    
    sd_j = hash[0:output_lambda] #size λ, first λ bits
    com_j = hash[output_lambda:] #size 2λ
    return sd_j, com_j

def H_1(commits:List[bytes], l:SECLambda) -> bytes:
    """H1 : {0, 1}∗ → {0, 1}2λ, collision-resistant hash function
    Hi(m) := SHAKE(m‖i, `), if i ∈ {0, 1, 3}

    Args:
        commits (List[bytes]): list of all com_j, each com_j is of size 2λ
        l (SECLambda): security parameter

    Returns:
        bytes: H_1 = shake( all com_j || i=1 , output_lenghth=2l )
    """
    # concatenate all com_j in commits
    m = b''.join(commits)
    m += (1).to_bytes(1, 'big')  # append i=1 as a byte
    shake = SHAKE128.new()
    shake.update(m)
    h = shake.read( (2*l)//8)
    
    return h

#========

def commit(r:bytes, iv:bytes, depth:int) -> Tuple[bytes, Decommitment, List[bytes]]:
    """VC.commit: code to generate one GGM tree and commitment leaves 

    Args:
        r (bytes): root seed of the GGM tree. Length = λ bits
        iv (bytes): iv for PRG and H0
        depth (int): depth of the GGM tree

    Returns:
        Tuple[bytes, Tuple[list[bytes], list[bytes]]]: _description_
    """
    
    ggm_tree_keys = create_empty_ggm_tree(depth)
    leaves = create_leaves(depth) # leaves to hold sd_j and their hashes/decommitments
    print(f"FUNC: commit: Initialised seeds (list[None] of size {len(leaves.seeds)}):  {leaves.seeds} \n and commitments (list of size {len(leaves.commitments)}) {leaves.commitments}")
    N = 2**depth

    ggm_tree_keys[0][0] = r # type: ignore #k^0_0 = r

    sec_lambda_value: SECLambda = 128
    # loop to fill in the GGM tree
    for i in range(1,depth+1):
        for j in range(0, 2**(i-1)):
            ggm_tree_keys[i][2*j] , ggm_tree_keys[i][(2*j) + 1]= PRG(ggm_tree_keys[i-1][j], iv, sec_lambda_value)

    #loop to fill in the exrta layer of leaves
    for j in range(0, N):
        leaves.seeds[j], leaves.commitments[j] = H_0(ggm_tree_keys[depth][j], iv, sec_lambda_value)
        
    h = H_1(leaves.commitments, sec_lambda_value)

    #decommitment information are the ggm tree nodes and the leaves commitments
    decommitments = Decommitment(nodes=ggm_tree_keys, commitments=leaves.commitments)

    return h, decommitments, leaves.seeds



r = get_random_bytes(128//8)
iv = get_random_bytes(128//8)
depth = 3
print("Running commitments test...")
h, decommitments, seeds = commit(r, iv, depth)
print("=== Commitments Test ===")
print(f"Commitment: {h!r}")
# print(f"Decommitments: {decommitments.nodes}, {decommitments.commitments}")
pprint(f"decommitments nodes: {len(decommitments.nodes)}")

print_nested(decommitments.nodes)