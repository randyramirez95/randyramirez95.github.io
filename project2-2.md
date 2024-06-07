---
layout: post
title: Network File Sharing & Network Security Group Configurations
description: 
image: assets/images/osticket.jpg
nav-menu: false
show_tile: false
---

In this tutorial, we explore the configuration and management of Active Directory users and organizational units, facilitating centralized user management and access control within the network infrastructure.

## **Environments and Technologies Used**

- [VMWare Workstation](https://www.vmware.com/content/vmware/vmware-published-sites/us/products/workstation-player/workstation-player-evaluation.html.html.html)
- Active Directory Domain Services

## Operating Systems Used

- Windows Server 2022
- Windows 11 Pro

## Prerequisites

- Active Directory set up and running
- Internet Connectivity
- Administrator Privileges

## Network File Sharing Configuration

Leveraging an environment with Active Directory enables administrators to establish secure file sharing and permissions management through the use of Network Security Groups (NSGs). By organizing users and resources into OUs within Active Directory, administrators can apply granular permissions to shared files and folders, ensuring that only authorized users have access to specific resources. Network Security Groups further enhance security by allowing administrators to define inbound and outbound traffic rules, restricting access based on IP address, port, or protocol. This integrated approach facilitates centralized management and enforcement of access control policies, enhancing the overall security posture of the network.

To illustrate these features we will create some sample file shares with various permissions, attempt to access file shares as a normal user, and finally create a security group with permissions set to test access.

First, we must login to our Windows Server VM, with either the initial login credentials or the User we created during our Active Directory installation. Then, we can create a set of folders within our C Drive and vary their sharing permissions to allow us to test further on:

- Folder: Read-Access ; Group: Domain Users ; Permissions: Read
- Folder: Write-Access ; Group: Domain Users ; Permissions: Read/Write
- Folder: No-Access ; Group: Domain Admins; Permissions: Read/Write
- Folder: Accounting ; Group: Accountants ; Permission: Read/Write

To set the sharing permissions we simply right click on the folder, and select **Properties**, and under the **Sharing** tab, we click **Share…**

Then we can specify who we want to share it with, either Domain Users or Domain Admins. 

Once we have added the folders and specified their sharing permissions, we can now login to the Windows 11 VM as one of the users that we created previously while setting up Active Directory. Once inside, we can open a **File Explorer**, and navigate to the folder corresponding to the Windows Server VM, which can vary from user to user, but in my case is **\\infost-adc**. This will open up the directory where we just setup our folders. 

To test the sharing permissions we can try to access the **No-Access** folder, which should be denied given our permissions: 

![Untitled](Network%20File%20Sharing%20&%20Network%20Security%20Group%20Conf%2093d136b8d5ae41aeb89c82825f6f123c/cb8bd303-32e1-4cbd-a941-2d304b25ec71.png)

Furthermore, we should be able to access and read the **Read-Access** folder, but unable to create any file within: 

![Untitled](Network%20File%20Sharing%20&%20Network%20Security%20Group%20Conf%2093d136b8d5ae41aeb89c82825f6f123c/Untitled.png)

Following our permissions, the **Write-Access** folder will allow us to read and create a folder and save it: 

![Untitled](Network%20File%20Sharing%20&%20Network%20Security%20Group%20Conf%2093d136b8d5ae41aeb89c82825f6f123c/Untitled%201.png)

## Network Security Group Configuration

First we can open **Active Directory Users and Computers** on our Windows Server VM, either through the **Server Manager** Tools or by searching for it. 

We will then create an new **Organizational Unit** named **Security Groups**, in which we will create a new group by selecting the **Security Groups OU**, and then right clicking the empty space to open a drop down menu: 

![Untitled](Network%20File%20Sharing%20&%20Network%20Security%20Group%20Conf%2093d136b8d5ae41aeb89c82825f6f123c/Untitled%202.png)

We can now assign permissions to the previously created folders via the created group, which in my case will be **Accountants**. We will head back to the C Drive to our **Accounting** folder and set its file sharing permissions accordingly: 

![Untitled](Network%20File%20Sharing%20&%20Network%20Security%20Group%20Conf%2093d136b8d5ae41aeb89c82825f6f123c/fbb8f605-08e7-435d-875a-92144dab6fc0.png)

Now we can add our Windows 11 user to this group by clicking on the **Accountants** group, heading over to the **Members**  tab, and clicking **Add…**

You can then enter their respective name into the text box and check the name. If available, you can click **OK**: 

![Untitled](Network%20File%20Sharing%20&%20Network%20Security%20Group%20Conf%2093d136b8d5ae41aeb89c82825f6f123c/Untitled%203.png)

To test these changes we must logout and log back in with the corresponding user on the Windows 11 VM. 

Congrats! You have now set Network File Sharing permissions while also adding Network Security Groups and tested their efficiency!

Feel free to check out my [other projects](https://randyramirez95.github.io/landing.html) for more detailed guides!