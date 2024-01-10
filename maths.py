from math import comb


class CombinationGenerator:
    def __init__(self, n_set):
        self.n_set = n_set

    # rank - index (mth combination)
    # n - set of n
    # k - chosen k at a time
    # https://gist.github.com/jonesinator/eed9614d2599921d5a4caffd7f2055bb
    def unrankFixedLengthCombination(self, n, k, rank):
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
        # Find length of k such that the rank is within the space of k-combination
        n = len(self.n_set)
        cumulative = 0
        found_k = 0
        for k in range(1, n + 1):
            cumulative += comb(n, k)
            found_k = k
            if rank < cumulative:
                break
        # Adjust rank to find position within k-combinations
        rank = (rank - cumulative) + comb(n, found_k)

        # Just a debug check to make sure algorithm will not fail, should never be called
        if rank >= comb(n, found_k):
            raise ValueError(
                f"New Rank {rank} is greater than or equal to the maximum rank for C({n},{found_k})")

        combination = self.unrankFixedLengthCombination(n, found_k, rank)

        return combination
