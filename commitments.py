from typing import Tuple, List, Literal
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import SHAKE128
from Crypto.Random import get_random_bytes
from dataclasses import dataclass
from pprint import pprint

type SECLambda = Literal[128, 192, 256]
type F_2 = Literal[0, 1]
type bitVectorJ = List[F_2] # bit vector of size depth [b_0, b_1, b_2, ..., b_(depth-1)]
type Hash = bytes
type Commitments = list[Hash]
type GGMTree = list[list[GGMTreeNode]] # GGM tree as a list of levels, each level is a list of bytes
type GGMTreeNode = bytes
type Seeds = bytes

@dataclass
class PartialDecommitment:
    cop: list[GGMTreeNode]  #list of sibling nodes from root to leaf
    com_j_star: Hash       #commitment at leaf j_star


@dataclass
class GGMTreeLeaves:
    seeds : List[Seeds]
    commitments : list[Hash]

@dataclass
class Decommitment:
    nodes: GGMTree #ggm tree nodes, the full GGM tree basically
    commitments: list[Hash] #list of commitments at leaves

def print_nested(lst, indent=0):
    '''Helper function to print nested lists nicely'''
    for item in lst:
        if isinstance(item, list):
            print("  " * indent + "[")
            print_nested(item, indent + 1)
            print("  " * indent + "]")
        else:
            print("  " * indent + str(item))


def create_empty_ggm_tree(depth: int) -> GGMTree:
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
    tree: GGMTree = []
    for level in range(depth + 1):
        level_nodes: list[ bytes] = []
        for _ in range(2 ** level):
            level_nodes.append(b'0')  # Initialize with placeholder bytes
        tree.append(level_nodes)
    print(f"FUNC: create_empty_ggm_tree: Created GGM tree with depth {depth}: {tree}")
    return tree


def create_leaves(depth: int) -> GGMTreeLeaves:
    """creates 2 lists, each of side 2**N. one to hold each of the seeds sd_j and another to hold the hashes of them

    Args:
        depth (int): depth of hte tree

    Returns:
        Tuple[List[None], List[None]]: _description_
    """
    n = 2 ** depth
    leaves = GGMTreeLeaves( seeds= [b'0'] * n , commitments= [b'0'] * n )
    return leaves
    # seeds: list[ bytes] = [b'0'] * n
    # commits:list[ bytes] = [b'0'] * n
    # return seeds, commits



# tree = create_empty_ggm_tree(depth=3)
# tree[0][0] = "dhajkshdjs"
# # print(tree)

def PRG(seed: GGMTreeNode, iv: bytes, output_lambda: SECLambda) -> Tuple[GGMTreeNode, GGMTreeNode]:
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

        k_1: GGMTreeNode = ct1
        k_2: GGMTreeNode = ct2

        return k_1, k_2
    else:
        raise NotImplementedError("PRG currently implemented only for output_lambda = 128")
    

def H_0(k_j_j:GGMTreeNode, iv:bytes, output_lambda:SECLambda) -> tuple[Seeds, Hash]:
    """H0 : {0, 1}^(λ+128) → {0, 1}λ * {0, 1}2λ, hash function for commitments_

    Args:
        k_j_j (bytes): _description_
        iv (bytes): _description_
        output_lambda (SECLambda): number of bits for security parameter. 

    Returns:
        tuple[bytes, bytes]: sj_j of size λ bits, com_j of size 2λ bits
    """
    #concatenate k_j_j and iv

    if len(k_j_j) != 16:
        raise ValueError(f"k_j_j must be 128 bits long, k_j_j{k_j_j} length is {len(k_j_j)}")
    if len(iv) != 16:
        raise ValueError("iv must be 128 bits long")
    

    shake  = SHAKE128.new()
    m = k_j_j + iv 
    i = (0).to_bytes(1, 'big')
    shake.update(m + i)
    
    hash = shake.read( (output_lambda+ (2*output_lambda)) //8)  
    
    
    sd_j: Seeds = hash[0:(output_lambda//8)] #size λ, first λ bits   
    if len(sd_j) != (output_lambda//8):
        raise ValueError("H_0: sd_j length mismatch")
    com_j: Hash = hash[(output_lambda//8):] #size 2λ
    if len(com_j) != (2*output_lambda)//8:
        raise ValueError("H_0: com_j length mismatch")
    
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
    
    ggm_tree_keys: GGMTree = create_empty_ggm_tree(depth)
    leaves : GGMTreeLeaves = create_leaves(depth) # leaves to hold sd_j and their hashes/decommitments
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



def NumRec(depth:int, bits_index:bitVectorJ)-> int:
    """depth of the tree and index of the leaf
    index = [b_0, b_1, b_2, ..., b_(depth-1)] where b_i is 0 or 1
    converts to a number in little endian format
    Args:
        depth (int): _description_
        index (list): _description_
    """
    total:int = 0
    for i in range(depth):
        total += bits_index[i] * (2**i)

    return total

def VC_Open(decommitments: Decommitment, bit_vector_j : bitVectorJ) -> PartialDecommitment:
    """_summary_

    Args:
        decommitments (Decommitment): _description_
        bit_vector_j (bitVectorJ): _description_

    Raises:
        ValueError: _description_
        ValueError: _description_

    Returns:
        _type_: _description_
        pdcom/patial decommitment is made up of:
        1. cop: list of sibling nodes from root to leaf
        2. com_j_star: commitment at leaf j_star
    """
    depth = len(decommitments.nodes) - 1 #3
    print(f"FUNC: VC_Open: depth of the tree is {depth}")
    j_star :int = NumRec(depth, bit_vector_j)

    a:int = 0
    cop : list[GGMTreeNode] = []
    for i in range(1, depth+1):  #1,2,3
        print(f"i is {i} ")
        cop.append (   decommitments.nodes[i][ (2*a) +  (bit_vector_j[depth-i] ^ 1)  ]   )#sibling node
        print(f" sibling node is k^{i}_ { (2*a) +  (bit_vector_j[depth-i] ^ 1)  }  ")
        a = 2*a + bit_vector_j[depth - i]
    
    if len(cop) != depth:
        raise ValueError("VC_Open: cop length mismatch")

    com_j_star: Hash = decommitments.commitments[j_star]
    if com_j_star == b'0':
        raise ValueError("VC_Open: com_j_star is not filled in properly, look at H_0 function")
    
    print(f"FUNC: VC_Open: com_j_star at index {j_star} is {com_j_star}")

    pdcom = PartialDecommitment(cop, com_j_star)
    return pdcom


def VC_reconstruct(pdecom : PartialDecommitment, bit_vector_j: bitVectorJ, iv:bytes) -> Tuple[Hash, list[Seeds]]:
    j_star : int = NumRec(len(bit_vector_j), bit_vector_j)
    depth= len(bit_vector_j) 
    a = 0 
    reconstructed_ggm_trees_keys = create_empty_ggm_tree(depth)
    reconstructed_ggm_trees_keys[0][0] = b'None'
    for i in range(1, depth+1):
        
        reconstructed_ggm_trees_keys[i][ (2*a) +  (bit_vector_j[depth-i] ^ 1)  ]   = pdecom.cop [i-1] # siblin node
        reconstructed_ggm_trees_keys[i][ (2*a) +  (bit_vector_j[depth-i])  ] = b'None' # We dont need this value for reconstruction

        for j in range(0, 2**(i-1)):
            if j == a:
                continue
            k_left, k_right = PRG(reconstructed_ggm_trees_keys[i-1][j], iv, 128)
            reconstructed_ggm_trees_keys[i][2*j] = k_left
            reconstructed_ggm_trees_keys[i][(2*j) + 1] = k_right
        
        a  = 2*a + bit_vector_j[depth - i]

    leaves : GGMTreeLeaves = create_leaves(depth)
    for j in range(0, 2**depth):
        if j == j_star:
            leaves.commitments[j] = pdecom.com_j_star
            leaves.seeds[j] = b'None'
        else:
            leaves.seeds[j], leaves.commitments[j] = H_0(reconstructed_ggm_trees_keys[depth][j], iv, 128)
        
    h: Hash = H_1(leaves.commitments, 128)

    return h, leaves.seeds



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
print(f"decommitments commitments: {decommitments.commitments}")

bit_vector: bitVectorJ= [1, 0, 1]
print(f"NumRec for index {bit_vector} is {NumRec(depth, bit_vector)}")

pdcom = VC_Open(decommitments, bit_vector)
print(f"Proof of decommitment: {pdcom}")

h_reconstrcted, seeds_reconstructed = VC_reconstruct(pdcom, bit_vector, iv)
print(f"Reconstructed commitment: {h_reconstrcted!r}")
print(f"Reconstructed seeds: {seeds_reconstructed}")

#is h == h_reconstrcted ?
print(f"Is original commitment equal to reconstructed commitment? {h == h_reconstrcted}")
