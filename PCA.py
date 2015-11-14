# -*- coding: utf-8 -*-
from numpy import *    

#参数1:特征值向量  
#参数2:比率  
#返回值：k(符合指定比率的topK k值)  
def setK(eigVals,rate = 0.9):  
    eigValInd = argsort(eigVals)  #对特征值进行排序  
    for i in range(1,eigVals.size+1):  
        topK = eigValInd[:-(i + 1):-1]  
        eigVal = eigVals[:, topK]  
        a = eigVal.sum()  
        b = eigVals.sum()  
        #print a/b  
        if a/b >= rate:  
            break;  
    return i  
  
#给定一个矩阵，返回 经PCA算法降过维的 矩阵（降维的程度由rate决定）  
#如果要指定k,可直接修改这条语句“ k = setK(eigVals,rate)”  
 
def pca(dataMat, rate=0.9):
	meanVals = mean(dataMat, axis=0) 
#	print "meanVals"
#	print meanVals
	meanRemoved = dataMat - meanVals #减去均值  
#	print "meanRemoved"
#	print meanRemoved
#	print "std"
#	print dataMat.std(0)
#	stded = meanRemoved / dataMat.std(0) #用标准差归一化  
	covMat = cov(meanRemoved, rowvar=0) #求协方差方阵  
#	print "covMat"
#	print covMat
	eigVals, eigVects = linalg.eig(mat(covMat)) #求特征值和特征向量  
#	print "eigVals"
#	print eigVals
#	print "eigVects"
#	print eigVects
	k = setK(eigVals,rate)   #get the topNfeat  
	eigValInd = argsort(eigVals)  #对特征值进行排序  
	eigValInd = eigValInd[:-(k + 1):-1]  #get topNfeat  
	redEigVects = eigVects[:, eigValInd]       # 除去不需要的特征向量  
	lowDDataMat = meanRemoved * redEigVects    #求新的数据矩阵  
	#reconMat = (lowDDataMat * redEigVects.T) * std(dataMat) + meanVals  #对矩阵还原  
	return lowDDataMat  
  
fo = open("./Rules/result.txt", "r")
lines = fo.readlines()
count = len(lines)
M = ones((count, 11))
for i in range(count):
	for j in range(11):
		M[i][j] = lines[i].split('\n')[0].split(' ')[j]
#print M
fo.close()
#print pca(M, 0.9)
lowDDataMat = pca(M, 0.9)
#print lowDDataMat
'''
fo_rules = open("./Rules/rules1.txt", "w");
for i in range(count):
	for j in lowDDataMat[i]:
		fo_rules.write(str(j))
		fo_rules.write(" ")
	fo_rules.write("\n")
fo_rules.close()
'''


#lowDDataMat.dump("../bishe/Result/rules.txt")
#print load("../bishe/Result/rules.txt")
#print load("../bishe/Result/rules.txt")[1]
#a = array([[2.5,2.4],[0.5,0.7],[2.2,2.9],[1.9,2.2],[3.1,3.0],[2.3,2.7],[2,1.6],[1,1.1],[1.5,1.6],[1.1,0.9]])  
#print "a:"  
#print a  
#print pca(a,0.9)  
  
#eigVals = array([3.735,1.133,0.457,0.323,0.199,0.153])  
#print setK(eigVals,0.6)  
