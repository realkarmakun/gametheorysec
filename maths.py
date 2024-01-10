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
        # Let's say C(4, 2) in 2^4 set, let's checkout rank of combination 4
        # Original combinoid is 4, should result in [0,1].
        # Cumulative would be 10 since C(4,1) + C(4,2) = 4+6 = 10
        # orignal_rank - cumulative = 4 - 10 = -6
        # We can see that resulting number is like inverted index for combinoid in C(4,2)
        # Proper rank should be in range of 0...C(4,2) which is 0...6
        # So we just add C(4,2) on top of our newly inverted rank: -6 + 6 = 0
        # Same would go for any consecutive number.
        # For example let's examine rank 5 in 2^4:
        # Original rank is 5, this should result in combination [0,2] in C(4,2) set
        # Cumulative is 10 since C(4,1) + C(4,2) = 4 + 6 = 10
        # 5 - 10 = -5 is inverted index of combinoid in C(4,2)
        # -5 + C(4,2) = -5 + 6 = 1 which is correct combinoid in C(4,2)
        rank = (rank - cumulative) + comb(n, found_k)

        # Just a debug check to make sure algorithm will not fail, should never be called
        if rank >= comb(n, found_k):
            raise ValueError(
                f"New Rank {rank} is greater than or equal to the maximum rank for C({n},{found_k})")

        combination = self.unrankFixedLengthCombination(n, found_k, rank)

        return combination
