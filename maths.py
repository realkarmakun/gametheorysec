from math import comb, log2, ceil


class CombinationGenerator:
    def __init__(self, n_set):
        self.n_set = n_set

    # rank - index (mth combination)
    # n - set of n
    # k - chosen k at a time
    def unrankFixedLengthCombination(self, rank, n, k):
        result = []
        a = n
        b = k
        x = (comb(n, k) - 1) - rank
        for i in range(0, k):
            a = a - 1
            while comb(a, b) > x:
                a = a - 1
            result.append(n - 1 - a)
            x = x - comb(a, b)
            b = b - 1
        return [self.n_set[i] for i in result]

    def unrankVaryingLengthCombination(self, rank):
        n = len(self.n_set)
        # Find length of k such that the rank is within the space of k-combination
        cumulative = 0
        found_k = 0
        for k in range(1, n):
            cumulative += comb(n, k)
            found_k = k
            if rank <= cumulative:
                break

        # Adjust rank to find position within k-combinations
        rank -= (cumulative - comb(n, found_k))

        combination = self.unrankFixedLengthCombination(rank, n, found_k)

        return combination
