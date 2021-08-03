# FeatureSync
About FeatureSync

As increasingly prevalent, more and more data are stored in the cloud storage, which brings us two major challenges. First, the modified files in the cloud should be quickly synchronized (sync) to ensure data consistency, e.g., delta sync achieves efficient cloud sync by synchronizing only the updated part of the file. Second, the huge data in the cloud needs to be deduplicated and encrypted, e.g., message-locked encryption (MLE) implements data deduplication by encrypting the content between different users. However, when both are combined, few updates in the content can cause large sync traffic amplification for both keys and ciphertext in the MLE-based cloud storage, which significantly degrading the cloud sync efficiency. In this paper, we propose an feature-based encryption sync scheme FeatureSync to improve the performance of synchronizing multiple encrypted files by merging several files before synchronizing. The performance evaluations on a lightweight prototype implementation of FeatureSync show that FeatureSync reduces the cloud sync time by 72.6% and the cloud sync traffic by 78.5% on average.

How to Build

1.unzip rsync.tar.xz get a folder

2.cd rsync build a rsync

3.cd tar & enc moduel build a tar

4.then look the example, and you should firstly setting rsync

How to Setting Rsync

You can see https://www.cnblogs.com/zhenhui/p/5715840.html
