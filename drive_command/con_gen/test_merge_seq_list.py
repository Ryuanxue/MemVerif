def merge_seq_list(list1,list2):
    pt1=0
    for e in list2:
        ele1=list1[pt1]
        if e==ele1:
            pt1=pt1+1
        elif e<ele1:
            list1.insert(pt1,e)
            pt1=pt1+1
        elif e>ele1:
            if e in list1:
                pt1=list1.index(e)
            else:
                len1=len(list1)
                for i in range(pt1,len1):
                    ele1=list1[i]
                    if ele1>e:
                        pt1=list1.index(ele1)
                        list1.insert(pt1,e)
                        pt1=pt1+1
                        break


if __name__ == '__main__':
    list1=[1,2,3,4,7,8,11,15]
    list2=[1,2,3,4,5,6,8,9,10,11,12,13,14]

    pt1=0
    for e in list2:
        ele1=list1[pt1]
        if e==ele1:
            pt1=pt1+1
        elif e<ele1:
            list1.insert(pt1,e)
            pt1=pt1+1
        elif e>ele1:
            if e in list1:
                pt1=list1.index(e)
            else:
                len1=len(list1)
                for i in range(pt1,len1):
                    ele1=list1[i]
                    if ele1>e:
                        pt1=list1.index(ele1)
                        list1.insert(pt1,e)
                        pt1=pt1+1
                        break
    for e in list1:
        print(e)

    for l in range(1,2):
        print(l)
