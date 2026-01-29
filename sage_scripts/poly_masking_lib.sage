# SPDX-License-Identifier: MIT
# Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck

# Compute sets of supports stable under the Frobenius automorphism for the AES field https://eprint.iacr.org/2011/413.pdf Appendix D.
# `ff` is the field and `n` the number of points to generate.
# only tested for GF(2^8) with AES irreducible polynomial.
def sample_frobenius_supports(ff, n, exclude=None, include_zero=True):
    c_s = []

    # ignore zero if requested
    start = 0 if include_zero else 1
    for s in range(start, (1<<8)):
        cs = [s]
        i = 1
        if s!=(1<<8)-1:
            while i==1 or cs[-1] % ((1<<8)-1) != s:
                cs.append(s*(1<<i))
                i = i+1
            cs[-1:] = []
        c_s.append(cs)

    set_C_s = set()
    for cs in c_s:
        set_s = set()
        for i in cs:
            if i==0:
                set_s.add(ff(0))
            else:
                set_s.add(ff.primitive_element()^i)
        set_C_s.add(frozenset(set_s))

    set_alpha = {1: [], 2: [], 4:[], 8:[]} #cardinal divides 8
    for s in set_C_s:
        if exclude is not None:
            if s.isdisjoint(exclude):
                set_alpha[len(s)].append(s)
        else:
            set_alpha[len(s)].append(s)

    # if exclude = None and include_zero = True then set_alpha has the following number of support-sets with size i: i=1:2, i=2:1, i=4:3, i=8:30

    # compute how many alpha-sets of size i are required to build the set of size `n`.
    requ = {8: min(floor(n/8), 30),\
            4: int((n%8)>>2&1) + (2 if floor(n/8) > 30 else 0),\
            2: (n%8)>>1&1,\
            1: (n%8)>>0&1}

    for i in reversed(requ.keys()):
        if requ[i] > len(set_alpha[i]):
            # there are not enough disjoint frobenius sets of size `i` to generate a frobenius set of size `n`
            num_missing_of_size_i = requ[i] - len(set_alpha[i])
            if i > 1 and i/2 in requ.keys() and (len(set_alpha[i/2]) - requ[i/2]) >= num_missing_of_size_i*2:
                print(f"trying to recover for i={i}")
                # it is possible to use 2 sets of size i/2 instead of 1 set of size i
                requ[i] -= num_missing_of_size_i
                requ[i/2] += num_missing_of_size_i*2
            # for i > 2 it is possible to use 4*i sets of size i/4 instead of 1 set of size i but there are not enough in th.
            else:
                raise AssertionError(f"Not enough disjoint Frobenius sets of size {i} to generate a Frobenius set of size {i}.\nThere are ways to cope with this (e.g., building it from smaller/larger sets) but they are not fully implemented.\nrequired: {requ}\navailable: {{8: {len(set_alpha[8])}, 4: {len(set_alpha[4])}, 2: {len(set_alpha[2])}, 1: {len(set_alpha[1])}}}.")
                # TODO: implement for all cases where there are not enough sets of size k but there are 2 sets of size (k/2) available and alternatively build it from larger sets - which requires to permute after squaring.

    alphas = [] # fixed alphas
    loops = [] # list of all the loops within fixed alphas
    map_loop = {} #mapping of each element to the loop which contains it + its position within the loop
    for i in requ.keys():
        for j in range(requ[i]):
            loops.append([])
            for e in set_alpha[i][j]: break #get an element of the set
            alphas.append(e)
            loops[-1].append(e)
            map_loop[e] = (len(loops)-1, 0)
            for jj in range(i-1):
                alphas.append(alphas[-1]**2)
                loops[-1].append(alphas[-1])
                map_loop[alphas[-1]] = (len(loops)-1, jj+1)

    return alphas

# Sample two disjoint sets of Frobenius support points of size k and n
def sample_support_points_for_secrets_and_shares(ff, k, n):
    # Frobenius support points of size k
    if k > 1:
        secrets_supports = sample_frobenius_supports(ff, k, include_zero=True)
    else:
        # by convention we pick zero as the support for the secret if there is only one secret encoded
        secrets_supports = [ff(0)]
    
    # generate different (disjoint) support points for the shares
    shares_supports = sample_frobenius_supports(ff, n, exclude=secrets_supports, include_zero=True)

    return secrets_supports, shares_supports

# test if a given set is stable under the Frobenius automorphism
def test_frobenius_stability(supports):
    # Test Frobenius stability for each support
    for s in supports:
        frobenius_image = s**2  
        assert frobenius_image in supports, f"Alpha not stable under Frobenius automorphism: {s} -> {frobenius_image}"

def test_all_sets_in_gf256(ff):
    for n in range(1, 256):
        supports = sample_frobenius_supports(ff, n)
        test_frobenius_stability(supports)
    print("All sets are stable under the Frobenius automorphism.")


# Return the permutation map for squaring using the Frobenius endomorphism.
def generate_permutation_map(supports):
    permutation = []

    for s in supports:
        squared = s**2

        # Find the index of the squared element in the supports list
        index = supports.index(squared)
        permutation.append(index)

    return permutation

# Return the Vandermonde matrix for `supports` restricted to `n` rows and `m` collumns.
def generate_vandermonde(ff, supports, n, m):
    v_square = matrix.vandermonde(supports[:n] + [0 for _ in range(max(n,m)-1)], ff)
    v_n_x_m = v_square.submatrix(0, 0, n, m)
    return v_n_x_m

def generate_A_tilde(ff, M_enc, num_secrets, degree):
    # truncate the first k=num_secret columns
    mat_d = M_enc.submatrix(0, num_secrets)

    mat_u = matrix(ff, degree+1-num_secrets, degree+1-num_secrets, 1)
    A_tilde = block_matrix([[mat_u], [mat_d]], subdivide=False)
    
    return A_tilde

def generate_Vs(ff, shares_supports, num_shares):
    V = generate_vandermonde(ff, shares_supports, num_shares, num_shares)
    V_inv = V.inverse()
    return V, V_inv

def generate_M_enc(ff, secrets_supports, shares_supports, num_shares, num_secrets, degree):
    U = generate_vandermonde(ff, secrets_supports + shares_supports[:degree+1-num_secrets], degree+1, degree+1)
    U_inv = U.inverse()
    V = generate_vandermonde(ff, shares_supports[degree+1-num_secrets:], num_shares-(degree+1-num_secrets), degree+1)
    M_enc = V * U_inv
    return M_enc

def generate_M_dec_initial(ff, secrets_supports, shares_supports, num_shares, num_secrets, degree):
    U = generate_vandermonde(ff, shares_supports[:degree+2], degree+1, degree+1)
    U_inv = U.inverse()
    V = generate_vandermonde(ff, secrets_supports, num_secrets, degree+1)
    M_dec = V * U_inv
    return M_dec

def generate_M_dec(ff, secrets_supports, shares_supports, num_shares, num_secrets, degree):
    U = generate_vandermonde(ff, secrets_supports[:degree+2], num_secrets, num_shares)
    V = generate_vandermonde(ff, shares_supports, num_shares, num_shares)
    V_inv = V.inverse()
    M_dec = U * V_inv
    return M_dec

def generate_M_lambda(ff, secrets_supports, shares_supports, num_shares, num_secrets, degree):
    # inverse of the vandermonde of the shares_supports
    # this is V_inverse
    mat_V_inv = generate_vandermonde(ff,shares_supports,num_shares,num_shares).inverse()

    # convert n shares into k secrets: V_inv
    # M_inv * n share = k secrets
    mat_M_inv = generate_vandermonde(ff,secrets_supports,num_secrets,num_shares)*mat_V_inv

    # mat_M_ext_inv * n shares = k secrets+ (degree+1-num_secrets) shares
    mat_u_d_plus_one_minus_k = matrix(ff, degree+1-num_secrets, degree+1-num_secrets, 1)
    mat_zero_d_plus_one_minus_k_times_n_minus_d_minus_1_plus_k = matrix(ff, degree+1-num_secrets, num_shares-(degree+1-num_secrets), 0)
    mat_M_ext_inv = block_matrix([[mat_M_inv],[mat_u_d_plus_one_minus_k,mat_zero_d_plus_one_minus_k_times_n_minus_d_minus_1_plus_k]],subdivide=False)

    mat_U_d_half_plus_one = generate_vandermonde(ff,secrets_supports+shares_supports[:floor(degree/2)+1-num_secrets],floor(degree/2)+1,floor(degree/2)+1)
    # inverse allows to go from k secrets + (d/2+1-k) shares, to coefficients of degree d/2 polynomial
    mat_U_d_half_plus_one_inv = mat_U_d_half_plus_one.inverse()
    mat_zero_d_half_plus_one_times_d_half = matrix(ff, floor(degree/2)+1, ceil(degree/2), 0)
    mat_zero_d_half_times_d_plus_one = matrix(ff, floor(degree/2),degree+1, 0)
    mat_U_d_plus_one_inv=block_matrix([[mat_U_d_half_plus_one_inv,mat_zero_d_half_plus_one_times_d_half],[mat_zero_d_half_times_d_plus_one]],subdivide=False)
    
    # coefficients of polynomial degree d/2 + 0...0 = mat_M_lambda_prime * n shares
    mat_M_lambda_prime = mat_U_d_plus_one_inv * mat_M_ext_inv

    # coefficients of polynomial degree d/2 = mat_M_lambda * n shares
    mat_M_lambda = mat_M_lambda_prime.submatrix(0,0,floor(degree/2)+1,-1)
    return mat_M_lambda


# used to redistribute part of the encoding of the split red input into the two polynomials F_cal' and F_cal''
def generate_lambda_hat_shamir_deg_red(V, V_inv, outdegree):
    # We truncate the Vandermonde matrix by only keeping the first d_2+1 columns
    # outdegree is generally floor(degree/2) of the global degree
    V_crop = V[:, :outdegree+1]

    # We truncate the inverse Vandermonde matrix by only keeping the first d_2+1 rows
    V_inv_crop = V_inv[:outdegree+1, :]
    
    lambda_degree_reduction = V_crop * V_inv_crop

    return lambda_degree_reduction

