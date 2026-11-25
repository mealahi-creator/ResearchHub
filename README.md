# ResearchHub — Master's & PhD progress tracker (MongoDB version)

ResearchHub tracks graduate students' progress: phase roadmap, meeting logs and blockers, an experiment board, a literature matrix, a publication pipeline, exams and reviews, uploaded files, and feedback from other professors.

## Who sees what

| Role | Can see | Can change |
|---|---|---|
| **Administrator** (you) | Every student | Everything, including accounts |
| **Supervisor** (e.g. a co-supervisor) | Only the students assigned to them | Those students' records |
| **Reviewer** (a professor checking progress) | Only the students assigned to them | Can post feedback only |
| **Student** | Only their own record | Their own logs, milestones, experiments, papers and files. They cannot write supervisor feedback, exam outcomes or their profile. |

Uploaded files (PDF, DOCX, XLSX, images, anything up to 25 MB each) are saved automatically in MongoDB (GridFS), next to the rest of the data.

---

## Setup (about 20 minutes, no coding)

### 1. Create the database (MongoDB Atlas, free)
1. Sign up at https://www.mongodb.com/atlas and create a **free (M0) cluster**.
2. **Database Access** → *Add New Database User* → choose a username and password. Save them.
3. **Network Access** → *Add IP Address* → **Allow access from anywhere** (`0.0.0.0/0`). Your hosting service's address changes, so this is needed. The database password still protects it.
4. **Database** → *Connect* → *Drivers* → copy the connection string. It looks like
   `mongodb+srv://USER:<password>@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority`
   Replace `<password>` with the password from step 2.

### 2. Put the code on GitHub
1. Create a new **private** repository on GitHub (for example `researchhub`).
2. Upload all the files from this folder (not `node_modules`, and never a `.env` file).

### 3. Host the app (Render, free plan)
1. Sign up at https://render.com with your GitHub account.
2. *New* → **Web Service** → pick your `researchhub` repository.
3. Settings: **Build command** `npm install`, **Start command** `npm start`.
4. Under **Environment**, add these variables:

| Key | Value |
|---|---|
| `MONGODB_URI` | the connection string from step 1 |
| `JWT_SECRET` | a long random string (60+ random letters and numbers) |
| `ADMIN_EMAIL` | your email, e.g. `mdeshrat.al@wu.ac.th` |
| `ADMIN_PASSWORD` | a strong password for your first sign-in |
| `ADMIN_NAME` | e.g. `Asst. Prof. Dr. Md Eshrat E Alahi` |
| `NODE_ENV` | `production` |
| `ANTHROPIC_API_KEY` | *(optional)* turns on the AI features, see below |

5. Click **Create Web Service**. After a few minutes you get an address like `https://researchhub-xxxx.onrender.com`. Sign in there with `ADMIN_EMAIL` and `ADMIN_PASSWORD`.

Your admin account is created only on the very first start. After that, change your password from the key icon. Changing `ADMIN_PASSWORD` later has no effect.

> On Render's free plan the app sleeps when nobody uses it, so the first visit after a break can take up to a minute. A paid plan (about $7/month) keeps it always on.

### 4. Add your students and colleagues
1. Click **Add Master's / PhD student** for each student. Their phase roadmap is created automatically.
2. Open **People & access** → **Add account**:
   - **Student**: choose which student record the account opens.
   - **Reviewer (professor)** or **Supervisor**: tick the students they may see.
3. The app shows a **temporary password** once. Copy it and send it to the person with the app address. On first sign-in they must choose their own password.

To remove someone's access, open their account and click **Disable**. They are signed out at once.

---

## Optional: AI features
With an Anthropic API key (https://console.anthropic.com → API Keys), set `ANTHROPIC_API_KEY` on Render. This turns on:
- **Lab briefing**: a weekly summary of all your students, with actions for you.
- **Meeting prep**: a summary of one student, their risks, and questions to ask in the meeting.
- **Upload progress**: Claude reads uploaded reports (DOCX, PDF, XLSX, TXT) and suggests milestones, meeting notes, experiments, papers and publications. You tick which ones to add.

API use is billed by Anthropic per request. Without a key, everything else works normally.

## Moving data from the earlier claude.ai version
In the old tracker, click **Backup → Copy backup**. In this app, click **Export → Import**, paste it, and click **Import**. The students are added and assigned to you.

## Storage limits
The free Atlas cluster holds 512 MB, which covers records for many students plus a few hundred typical documents. If files start filling it up, upgrade the Atlas cluster, or keep big files (videos, datasets) in Google Drive and use **Add link** in the Files tab.

## Running on your own computer (optional)
Install Node.js 18+, copy `.env.example` to `.env` and fill it in, then:
```
npm install
npm start
```
Open http://localhost:3000.

## Files
- `server.js`: the server (sign-in, access rules, data, file storage, AI)
- `public/index.html`: the app people use in the browser
- `.env.example`: the settings you need to fill in
