# Code from https://stackoverflow.com/questions/26381220/python-bubble-sort-list-with-swap-count
def perform_bubble_sort(blist):
    cmpcount, swapcount = 0, 0
    for j in range(len(blist)):
        for i in range(1, len(blist)-j):
            cmpcount += 1
            if blist[i-1] > blist[i]:
                swapcount += 1
                blist[i-1], blist[i] = blist[i], blist[i-1]
    return swapcount
