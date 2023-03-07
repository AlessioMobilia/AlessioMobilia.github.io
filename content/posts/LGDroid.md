---
title: CyberDefence - LGDroid
date: 2023-03-07T18:00:39+01:00
draft: false
categories:
  - Walkthrough
tags:
  - Writeup
  - Walkthrough
  - Mobile
  - Android
  - CyberDefence
---

# Introduction

Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/69#nav-questions

Setup: Linux Machine

## Tool Used

- [Autopsy](https://www.autopsy.com/): a good free forensics tool to navigate filesystems on Linux.
-  [Epoch Converter](https://www.epochconverter.com/): This website permits the conversion of the time from the Unix Epoch Time to a human-readable format.




# Solution

I suggest trying the challenge by yourself before reading this post.
But if you are stuck reading some write-up is a good way to learn new things.

## Q1 What is the email address of Zoe Washburne?

I have opened the image inside Autopsy.
Inside the folder **Agent Data** there is a database file called **contacts3.db**:
![](/images/LGDroid/LGDroidQ1.png)

With Autopsy you can navigate the db, or you can use external tools like *DB Browser for SQLite*.
I have used Autopsy for this.
Inside the file, there is the email of Zoe Washburne.

**The answer is:**
> zoewash@0x42.null


## Q2 What was the device time in UTC at the time of acquisition? (hh:mm:ss)


Inside **Live Data** there is a file called **device_datetime_utc.txt**
This file contains the time of the machine when it was dumped.

![LGDroidQ2](/images/LGDroid/LGDroidQ2.png)

**The answer is:**
> 18:17:56


## Q3 What time was Tor Browser downloaded in UTC? (hh:mm:ss)

In **Agent Data** there is the database **download.db** 
It is easy to see the download time. But it is in Unix Epoch Time.


![LGDroidQ3](/images/LGDroid/LGDroidQ3.png)

With the tool https://www.epochconverter.com/ I converted the time into a human-readable format.

**The answer is:**
> 19:42:26



## Q4 What time did the phone charge to 100% after the last reset? (hh:mm:ss)

inside *Live Data/Dumpsys Data/batterystats.txt* there is some information about the battery stats and the charge times. This took me some time to understand how to read this file.
There is the time of the reset time:

![LGDroidQ4_1](/images/LGDroid/LGDroidQ4_0.png)

and the delay after which the phone reached the full charge:
![LGDroidQ4_1](/images/LGDroid/LGDroidQ4_1.png)

So adding the delay to the reset time I have found the solution:

**The answer is:**
> 13:17:20



## Q5 What is the password for the most recently connected WIFI access point?

in  *adb-data/com.andorid.providers.settings/k/com.android.providers.settings.data* there is the useful data we are searching for:
![](/images/LGDroid/LGDroidQ5.png)

![](/images/LGDroid/LGDroidQ5_1.png)


**The answer is:**
> ThinkingForest!



## Q6 What app was the user focused on at 2021-05-20 14:13:27?


in *Live_Data/usage_stats.txt* we find all the information of the application running on the device:

![](/images/LGDroid/LGDroidQ6.png)

I just searched in the file for the time requested by the question.

**The answer is:**
> youtube



## Q7 How much time did the suspect watch Youtube on 2021-05-20? (hh:mm:ss)

I have simply checked the difference between the time in which the app was moved to the foreground and the time in with it was moved to the background:

![](/images/LGDroid/LGDroidQ7.png)

22:47:57 - 14:13:27 = 08:34:30

**The answer is:**

> 08:34:30


## Q8 "suspicious.jpg: What is the structural similarity metric for this image compared to a visually similar image taken with the mobile phone? (#.##).


I have found this: https://ourcodeworld.com/articles/read/991/how-to-calculate-the-structural-similarity-index-ssim-between-two-images-with-python

seems the easiest way to calculate the SSIM for two images.

so i have installed the libraries required:

```bash
pip3 install scikit-image opencv-python imutils
```



with a little modification to work with new libraries (i have just modified the import line):

```python
# Usage:
#
# python3 script.py --input original.png --output modified.png
# Based on: https://github.com/mostafaGwely/Structural-Similarity-Index-SSIM-

# 1. Import the necessary packages
from skimage.metrics import structural_similarity as compare_ssim
import argparse
import imutils
import cv2

# 2. Construct the argument parse and parse the arguments
ap = argparse.ArgumentParser()
ap.add_argument("-f", "--first", required=True, help="Directory of the image that will be compared")
ap.add_argument("-s", "--second", required=True, help="Directory of the image that will be used to compare")
args = vars(ap.parse_args())

# 3. Load the two input images
imageA = cv2.imread(args["first"])
imageB = cv2.imread(args["second"])

# 4. Convert the images to grayscale
grayA = cv2.cvtColor(imageA, cv2.COLOR_BGR2GRAY)
grayB = cv2.cvtColor(imageB, cv2.COLOR_BGR2GRAY)

# 5. Compute the Structural Similarity Index (SSIM) between the two
#    images, ensuring that the difference image is returned
(score, diff) = compare_ssim(grayA, grayB, full=True)
diff = (diff * 255).astype("uint8")

# 6. You can print only the score if you want
print("SSIM: {}".format(score))
```

After running the code I have found the answer:

![](/images/LGDroid/LGDroidQ8.png)

This is what I expected because the images are practically the same.

**The answer is:**

> 0.99

