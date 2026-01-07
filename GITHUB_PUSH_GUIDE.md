# GitHub Push Guide

Your projects are now ready to be pushed to GitHub! Follow these steps:

## Step 1: Create a GitHub Repository

1. Go to [GitHub.com](https://github.com) and log in (or create an account)
2. Click the **"+" icon** in the top right corner
3. Select **"New repository"**
4. Fill in the repository details:
   - **Repository name**: `Cybersecurity-Projects` (or your preferred name)
   - **Description**: `Security tools portfolio: Web Vulnerability Scanner and Intrusion Detection System`
   - **Public/Private**: Choose Public (recommended for portfolio)
   - **Do NOT** initialize with README, .gitignore, or license
5. Click **"Create repository"**

## Step 2: Add the Remote Repository

After creating the repository, GitHub will show commands. In your terminal, run:

```powershell
cd "c:\Users\Mohamed\source\repos\Cybersecurity project"

# Add the remote repository (replace YOUR_USERNAME with your GitHub username)
&"C:\Program Files\Git\bin\git.exe" remote add origin https://github.com/YOUR_USERNAME/Cybersecurity-Projects.git

# Rename branch to main (if needed)
&"C:\Program Files\Git\bin\git.exe" branch -M main

# Push to GitHub
&"C:\Program Files\Git\bin\git.exe" push -u origin main
```

## Step 3: GitHub Authentication

When pushing, you'll be prompted for authentication. You have two options:

### Option A: Personal Access Token (Recommended)
1. Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Click **"Generate new token"**
3. Select scopes: `repo` (full control of private repositories)
4. Copy the token and paste it as the password when prompted

### Option B: SSH Key (More Secure)
1. Generate SSH key:
```powershell
ssh-keygen -t ed25519 -C "your-email@example.com"
```
2. Add to GitHub: Settings → SSH and GPG keys → New SSH key
3. Test connection:
```powershell
ssh -T git@github.com
```
4. Use SSH URL instead: `git@github.com:YOUR_USERNAME/Cybersecurity-Projects.git`

## Step 4: Verify Push Success

Check your GitHub repository in the browser. You should see:
- ✅ Web-Vulnerability-Scanner folder
- ✅ Intrusion-Detection-System folder  
- ✅ .gitignore file
- ✅ All project files

## Current Git Status

- **Repository Location**: `C:\Users\Mohamed\source\repos\Cybersecurity project`
- **Current Branch**: master
- **Commits**: 1
- **Files Tracked**: 8
- **Status**: Ready to push

## Future Commits

After pushing to GitHub, you can make updates:

```powershell
# Make your changes, then:
git add .
git commit -m "Your message here"
git push
```

## Troubleshooting

### Forgot repository name?
```powershell
&"C:\Program Files\Git\bin\git.exe" remote -v
```

### Change remote URL?
```powershell
&"C:\Program Files\Git\bin\git.exe" remote set-url origin https://github.com/YOUR_USERNAME/NEW_REPO_NAME.git
```

### Reset to commit to another repo?
```powershell
&"C:\Program Files\Git\bin\git.exe" remote remove origin
&"C:\Program Files\Git\bin\git.exe" remote add origin NEW_URL
&"C:\Program Files\Git\bin\git.exe" push -u origin main
```

---

**Your projects are now version controlled and ready to showcase on GitHub!** 🚀
