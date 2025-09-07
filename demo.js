// school-bot.js
const { Telegraf, Markup, session, Scenes } = require('telegraf');
const mongoose = require('mongoose');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch');
require('dotenv').config();



// --- Continue with the rest of your code --


// --- MongoDB Connection ---
const MONGODB_URI = process.env.MONGODB_URI || 
  'mongodb+srv://cluster0.7nynrxw.mongodb.net/school_system_bot?retryWrites=true&w=majority&appName=Cluster0&connectTimeoutMS=30000&socketTimeoutMS=45000'; 
// Retry connection with exponential backoff
const connectWithRetry = () => {
    console.log('MongoDB connection attempt...');
    mongoose.connect(MONGODB_URI).catch(err => {
        console.error('MongoDB connection error:', err);
        setTimeout(connectWithRetry, 5000);
    });
}; 

connectWithRetry();

mongoose.connection.on('connected', () => {
    console.log('✅ Connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err);
});


const studentListRequestSchema = new mongoose.Schema({
  teacherId: {
    type: String,
    required: true,
  },
  teacherTelegramId: {
    type: Number, // Telegram user ID is a number
    required: true,
    index: true,
  },
  className: {
    type: String,
    required: true,
    index: true,
  },
  subject: {
    type: String,
    required: true,
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'denied'],
    default: 'pending',
    index: true,
  },
  requestDate: {
    type: Date,
    default: Date.now,
  },
  approvalDate: Date,
  approvedBy: {
    type: Number, // Admin Telegram ID who approved/denied
  }
}, { timestamps: true });

const StudentListRequest = mongoose.model('StudentListRequest', studentListRequestSchema);

// Grade Schema
const gradeSchema = new mongoose.Schema({
    gradeId: { type: String, required: true, unique: true },
    studentId: { type: String, required: true },
    studentName: { type: String, required: true },
    teacherId: { type: String, required: true },
    teacherName: { type: String, required: true },
    subject: { type: String, required: true },
    score: { type: Number, required: true, min: 0, max: 100 },
    purpose: { type: String, required: true, enum: ['quiz', 'test', 'assignment', 'exam', 'project'] },
    date: { type: Date, default: Date.now },
    comments: { type: String, default: '' }
}, { timestamps: true });

const Grade = mongoose.model('Grade', gradeSchema);
// OTP Schema for teacher registration
const otpSchema = new mongoose.Schema({
    telegramId: { type: String, required: true, unique: true, sparse: true },
    otp: { type: String, required: true },
    code: { type: String, sparse: true }, // Add this if needed
    expiresAt: { type: Date, required: true },
    attempts: { type: Number, default: 0 },
    verified: { type: Boolean, default: false }
}, { timestamps: true });

const OTP = mongoose.model('OTP', otpSchema);

// Teacher Login Schema
const teacherLoginSchema = new mongoose.Schema({
    teacherId: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    lastLogin: { type: Date },
    loginAttempts: { type: Number, default: 0 },
    lockedUntil: { type: Date }
}, { timestamps: true });

const TeacherLogin = mongoose.model('TeacherLogin', teacherLoginSchema);
//user schema
const userSchema = new mongoose.Schema({
    telegramId: { type: String, required: true, unique: true, sparse: true },
    username: { type: String },
    name: { type: String, default: 'User' },
    role: { type: String, enum: ['user', 'admin', 'parent', 'teacher'], default: 'user' },
    adminId: { type: String, unique: true, sparse: true},
    studentIds: [{ type: String }],
    subjects: [{ type: String }],
    pendingStudentIds: [{ type: String }]
}, { timestamps: true });

// 


// Update the student schema
const studentSchema = new mongoose.Schema({
    studentId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    class: { type: String, required: true },
    parentId: { type: String, default: null },
    pendingParentId: { type: String, default: null },
}, { timestamps: true });

const teacherSchema = new mongoose.Schema({
    banned: { type: Boolean, default: false },

    teacherId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    telegramId: { 
        type: String, default:"", 
        unique: true, 
        sparse: true // This allows multiple null values
    },
    
    subjects: [{ type: String }],
    pendingSubjects: [{ type: String }]
}, { timestamps: true });

// Create the sparse index explicitly
teacherSchema.index({ telegramId: 1 }, { sparse: true, unique: true, sparse: true });

const uploadedFileSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    originalName: { type: String, required: true },
    storedName: { type: String, required: true },
    uploadDate: { type: Date, default: Date.now },
    processed: { type: Boolean, default: false },
    classAssigned: { type: String, required: true }
});
// Teacher-Student Relationship Schema
const teacherStudentSchema = new mongoose.Schema({
    teacherId: { type: String, required: true },
    teacherName: { type: String, required: true },
    studentId: { type: String, required: true },
    studentName: { type: String, required: true },
    subject: { type: String, required: true },
    className: { type: String, required: true },
    addedDate: { type: Date, default: Date.now }
}, { timestamps: true });

// Compound index to prevent duplicates
teacherStudentSchema.index({ teacherId: 1, studentId: 1, subject: 1 }, { unique: true });

const TeacherStudent = mongoose.model('TeacherStudent', teacherStudentSchema);


// --- Models ---
const User = mongoose.model('User', userSchema);
const Student = mongoose.model('Student', studentSchema);
const Teacher = mongoose.model('Teacher', teacherSchema);
const UploadedFile = mongoose.model('UploadedFile', uploadedFileSchema);
//helper Functions

// Helper function to check if user is registered as teacher
const isUserRegisteredTeacher = async (telegramId) => {
    try {
        const teacher = await Teacher.findOne({ telegramId });
        return teacher !== null;
    } catch (error) {
        console.error('Error checking teacher registration:', error);
        return false;
    }
};
// Clean up expired OTPs every hour
setInterval(async () => {
    try {
        const result = await OTP.deleteMany({ 
            expiresAt: { $lt: new Date() } 
        });
        
        if (result.deletedCount > 0) {
            console.log(`Cleaned up ${result.deletedCount} expired OTPs`);
        }
    } catch (error) {
        console.error('Error cleaning up expired OTPs:', error);
    }
}, 60 * 60 * 1000); // Run every hour


// Add this helper function to get rich teacher information
const getRichTeacherInfo = async (telegramId) => {
    try {
        const teacher = await Teacher.findOne({ telegramId });
        if (!teacher) return null;

        // Get student count and subject statistics
        const subjectStats = await TeacherStudent.aggregate([
            { $match: { teacherId: teacher.teacherId } },
            { $group: {
                _id: '$subject',
                studentCount: { $sum: 1 }
            }},
            { $sort: { studentCount: -1 } }
        ]);

        const studentCount = subjectStats.reduce((sum, stat) => sum + stat.studentCount, 0);

        return {
            name: teacher.name,
            teacherId: teacher.teacherId,
            telegramId: teacher.telegramId,
            username: teacher.username,
            subjects: teacher.subjects || [],
            subjectStats: subjectStats,
            studentCount: studentCount,
            registrationDate: teacher.createdAt
        };
    } catch (error) {
        console.error('Error getting rich teacher info:', error);
        return null;
    }
};
// Add this helper function to format list information
const getFormattedListInfo = async (teacherId, className) => {
    const listInfo = await TeacherStudent.aggregate([
        { $match: { teacherId: teacherId, className: className } },
        { $group: {
            _id: null,
            totalStudents: { $sum: 1 },
            subjects: { $addToSet: '$subject' },
            firstAdded: { $min: '$addedDate' },
            lastAdded: { $max: '$addedDate' },
            studentNames: { $push: '$studentName' }
        }}
    ]);

    if (listInfo.length === 0) return null;

    return {
        totalStudents: listInfo[0].totalStudents,
        subjects: listInfo[0].subjects,
        subjectCount: listInfo[0].subjects.length,
        firstAdded: listInfo[0].firstAdded,
        lastAdded: listInfo[0].lastAdded,
        sampleStudents: listInfo[0].studentNames.slice(0, 5) // First 5 students
    };
};
const getUniqueClasses = async () => {
    try {
        const classes = await Student.distinct('class');
        return classes.filter(className => className && className.trim() !== '');
    } catch (err) {
        console.error('Error getting unique classes:', err);
        return [];
    }
};
const processTeacherStudentUpload = async (ctx, studentIds, subject) => {
    const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
    if (!teacher) {
        return ctx.reply('❌ Teacher profile not found. Please contact an admin.');
    }

    const { teacherId, name: teacherName } = teacher;
    let successfulCreations = 0;
    let failedCreations = 0;
    const failedStudents = [];

    for (const studentId of studentIds) {
        try {
            const student = await Student.findOne({ studentId });
            if (student) {
                // Check if the relationship already exists to prevent duplicates
                const existingRelation = await TeacherStudent.findOne({
                    teacherId,
                    studentId,
                    subject
                });

                if (!existingRelation) {
                    const newRelation = new TeacherStudent({
                        teacherId,
                        teacherName,
                        studentId,
                        studentName: student.name,
                        subject,
                        className: student.class
                    });
                    await newRelation.save();
                    successfulCreations++;
                } else {
                    // It's not a failure, just a duplicate that we don't need to add again
                    successfulCreations++;
                }
            } else {
                failedCreations++;
                failedStudents.push(studentId);
            }
        } catch (error) {
            if (error.code === 11000) { // MongoDB duplicate key error
                // This case is already handled by the findOne check, but good to have
                // a fallback just in case.
                successfulCreations++;
            } else {
                console.error(`Error creating relationship for student ${studentId}:`, error);
                failedCreations++;
                failedStudents.push(studentId);
            }
        }
    }

    let replyMessage = `✅ Finished processing student list.\n\n`;
    replyMessage += `• Successful links created: ${successfulCreations}\n`;
    replyMessage += `• Failed to link (student ID not found): ${failedCreations}\n`;

    if (failedStudents.length > 0) {
        replyMessage += `\n❌ The following IDs could not be found:\n`;
        replyMessage += failedStudents.join(', ');
    }

    ctx.reply(replyMessage);
    ctx.scene.leave();
};




const getUserByUsername = async (username) => {
    try {
        // This assumes usernames are stored in the name field
        // Adjust based on your actual schema
        return await User.findOne({ 
            name: new RegExp(`^${username}$`, 'i')
        });
    } catch (err) {
        console.error('Error getting user by username:', err);
        return null;
    }
};

// --- Models ---

// --- Bot Initialization ---
const bot = new Telegraf(process.env.BOT_TOKEN);
console.log('School System Bot is running...');

// --- Input Validation Functions ---
const isValidStudentId = (id) => {
    return /^ST-?\d{4}$/i.test(id);
};

const isValidTeacherId = (id) => /^TE\d{4}$/.test(id);
const isValidAdminId = (id) => /^AD\d{2}$/.test(id);

const isValidTelegramId = (id) => /^\d+$/.test(id);
const isValidName = (name) => name && name.trim().length > 0 && name.trim().length <= 100;
const isValidClassName = (className) => className && className.trim().length > 0 && className.trim().length <= 50;
const isValidSubject = (subject) => subject && subject.trim().length > 0 && subject.trim().length <= 50;


const isValidAnnouncementOrMessage = (text) => text && text.trim().length > 0;

// --- Helper Functions ---

const getUserById = async (telegramId) => {
    try {
        return await User.findOne({ telegramId });
    } catch (err) {
        console.error('Error getting user by ID:', err);
        return null;
    }
};

const getStudentById = async (studentId) => {
    try {
        return await Student.findOne({ studentId });
    } catch (err) {
        console.error('Error getting student by ID:', err);
        return null;
    }
};

const getStudentsByParentId = async (parentId) => {
    try {
        return await Student.find({ parentId });
    } catch (err) {
        console.error('Error getting students by parent ID:', err);
        return [];
    }
};

const getTeacherById = async (teacherId) => {
    try {
        return await Teacher.findOne({ teacherId });
    } catch (err) {
        console.error('Error getting teacher by ID:', err);
        return null;
    }
};

const getAdmins = async () => {
    try {
        return await User.find({ role: 'admin' });
    } catch (err) {
        console.error('Error getting admins:', err);
        return [];
    }
};

// Unique ID Generators
// --- Helper Functions ---
//
//
//

const getLoginMenu = async (telegramId) => {
    const user = await getUserById(telegramId);
    if (user) {
        switch (user.role) {
            case 'teacher':
                return teacherMenu;
            case 'admin':
                return adminMenu;
            case 'parent':
                return parentMenu;
            default:
                return loginMenu;
        }
    }
    return loginMenu;
};
// Authorization middleware for teacher routes
// Authorization middleware for teacher routes - FIXED VERSION
const requireTeacherAuth = async (ctx, next) => {
    try {
        // First check if user is already a registered teacher
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (teacher.banned) {
    ctx.reply('❌ Your access has been banned. Please contact an administrator.');
    return;
  }

        if (teacher) {
            // User is a registered teacher, check user role
            const user = await getUserById(ctx.from.id);
            if (user && user.role === 'teacher') {
                ctx.state.teacher = teacher;
                return next();
            } else {
                // Teacher exists but user role is wrong - fix it
                if (user) {
                    user.role = 'teacher';
                    await user.save();
                    ctx.state.teacher = teacher;
                    return next();
                }
            }
        }
        
        // If not a teacher, show appropriate message
        ctx.reply('❌ You are not registered as a teacher yet. Please use the "👨‍🏫 Teacher Registration" option first.', loginMenu);
        
    } catch (error) {
        console.error('Authorization error:', error);
        ctx.reply('❌ An error occurred during authorization. Please try again.');
    }
};

// Generate 6-digit OTP
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

// Generate 6-digit password
const generatePassword = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

// Check if OTP is expired
const isOTPExpired = (expiresAt) => {
    return new Date() > expiresAt;
};

// Hash password (simple implementation)
const hashPassword = (password) => {
    return crypto.createHash('sha256').update(password).digest('hex');
};

// Verify password
const verifyPassword = (password, hashedPassword) => {
    return hashPassword(password) === hashedPassword;
};

// Check if account is locked
const isAccountLocked = (lockedUntil) => {
    return lockedUntil && new Date() < lockedUntil;
};

const viewStudentGrades = async (studentId, subject = null) => {
    try {
        const student = await getStudentById(studentId);
        if (!student) return null;
        
        const grades = await getStudentGrades(studentId, subject);
        
        return {
            student: student.name,
            studentId: student.studentId,
            class: student.class,
            grades: grades.map(grade => ({
                subject: grade.subject,
                score: grade.score,
                purpose: grade.purpose,
                date: grade.date,
                comments: grade.comments,
                teacher: grade.teacherName
            }))
        };
    } catch (error) {
        console.error('Error viewing student grades:', error);
        return null;
    }
};
// Get students by teacher and subject
const getStudentsByTeacherAndSubject = async (teacherId, subject) => {
    try {
        return await TeacherStudent.find({ 
            teacherId, 
            subject 
        }).sort({ studentName: 1 }); // Sort alphabetically
    } catch (err) {
        console.error('Error getting students by teacher and subject:', err);
        return [];
    }
};

// Get student grades
const getStudentGrades = async (studentId, subject = null) => {
    try {
        const query = { studentId };
        if (subject) query.subject = subject;
        return await Grade.find(query).sort({ date: -1 });
    } catch (err) {
        console.error('Error getting student grades:', err);
        return [];
    }
};

// Generate unique grade ID
const generateUniqueGradeId = async () => {
    let gradeId;
    let exists;
    do {
        const randomDigits = crypto.randomInt(1000, 9999).toString();
        gradeId = `GR${randomDigits}`;
        exists = await Grade.findOne({ gradeId });
    } while (exists);
    return gradeId;
};

// Update the unique ID generators

// Student ID generator: ST + 4 digits (e.g., ST3412)
const generateUniqueStudentId = async () => {
    let studentId;
    let exists;
    do {
        const randomDigits = crypto.randomInt(1000, 9999).toString();
        studentId = `ST${randomDigits}`;
        exists = await Student.findOne({ studentId });
    } while (exists);
    return studentId;
};

// Teacher ID generator: TE + 4 digits (e.g., TE4001)
const generateUniqueTeacherId = async () => {
    let teacherId;
    let exists;
    do {
        const randomDigits = crypto.randomInt(1000, 9999).toString();
        teacherId = `TE${randomDigits}`;
        exists = await Teacher.findOne({ teacherId });
    } while (exists);
    return teacherId;
};

// Admin ID generator: AD + 2 digits (e.g., AD12)
const generateUniqueAdminId = async () => {
    let adminId;
    let exists;
    do {
        const randomDigits = crypto.randomInt(10, 99).toString();
        adminId = `AD${randomDigits}`;
        exists = await User.findOne({ adminId }); // Assuming you might want to store admin IDs
    } while (exists);
    return adminId;
};



// --- State Management ---
const { leave } = Scenes.Stage;
const stage = new Scenes.Stage();

bot.use(session());
bot.use(stage.middleware());
// --- Scene Definitions --------------------------------------
//
//
//
//
//
//
//
//
//

const requestStudentsListScene = new Scenes.BaseScene('request_students_list_scene');

requestStudentsListScene.enter(async (ctx) => {
  try {
    const classes = await getUniqueClasses();
    if (classes.length === 0) {
      ctx.reply('❌ No classes available.');
      return ctx.scene.leave();
    }
    const buttons = classes.map(cls => [Markup.button.callback(cls, `select_class_${cls.replace(/ /g, '_')}`)]);
    buttons.push([Markup.button.callback('❌ Cancel', 'cancel_request_students_list')]);
    await ctx.reply('📚 Select the class for which you want to request the student list:', Markup.inlineKeyboard(buttons));
  } catch (error) {
    console.error('Error fetching classes:', error);
    ctx.reply('❌ Could not fetch classes. Try again later.');
    ctx.scene.leave();
  }
});

requestStudentsListScene.action(/^select_class_(.+)$/, async (ctx) => {
  const className = ctx.match[1].replace(/_/g, ' ');
  ctx.session.requestClass = className;

  const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
  const currentSubjects = teacher.subjects || [];
  if (currentSubjects.length === 0) {
    await ctx.reply('❌ You have no subjects assigned.');
    return ctx.scene.leave();
  }

  const subjectButtons = currentSubjects.map(subject => [Markup.button.callback(subject, `select_subject_${subject.replace(/ /g, '_')}`)]);
  subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_request_students_list')]);

  await ctx.reply(`📖 You selected class "${className}". Now select the subject:`, Markup.inlineKeyboard(subjectButtons));
});

requestStudentsListScene.action(/^select_subject_(.+)$/, async (ctx) => {
  const subject = ctx.match[1].replace(/_/g, ' ');
  ctx.session.requestSubject = subject;

  await ctx.reply(`✅ Confirm your request:\n\nClass: *${ctx.session.requestClass}*\nSubject: *${subject}*\n\nType CONFIRM to proceed or CANCEL to abort.`, { parse_mode: 'Markdown' });
  ctx.session.awaitingConfirmation = true;
});

requestStudentsListScene.on('text', async (ctx) => {
  if (!ctx.session.awaitingConfirmation) {
    return ctx.reply('❌ Please select a class and subject first.');
  }

  const input = ctx.message.text.trim().toUpperCase();
  if (input === 'CANCEL' || input === '❌ CANCEL') {
    await ctx.reply('❌ Request cancelled.', teacherMenu);
    return ctx.scene.leave();
  }
  if (input !== 'CONFIRM') {
    return ctx.reply('❌ Please type CONFIRM to submit or CANCEL to abort.');
  }

  try {
    // Save request in DB
    
    const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
    if (!teacher) {
      ctx.reply('❌ Teacher profile not found.');
      return ctx.scene.leave();
    }

    // Create new request
    const newRequest = new StudentListRequest({
      teacherId: teacher.teacherId,
      teacherTelegramId: ctx.from.id,
      className: ctx.session.requestClass,
      subject: ctx.session.requestSubject,
    });

    await newRequest.save();

    // Notify admins about new request (admins code assumed available)
    const admins = await User.find({ role: 'admin' });
    for (const admin of admins) {
      try {
        
        await ctx.telegram.sendMessage(
  admin.telegramId,
  `📋 *Student List Request*\n\n` +
  `Teacher: ${teacher.name} (${teacher.teacherId})\n` +
  `Class: ${ctx.session.requestClass}\n` +
  `Subject: ${ctx.session.requestSubject}\n` +
  `Use the buttons below to Approve or Deny.`,
  {




    parse_mode: 'Markdown',
    ...Markup.inlineKeyboard([
      Markup.button.callback('✅ Approve', `approve_request_${newRequest._id}`),
      Markup.button.callback('❌ Deny', `deny_request_${newRequest._id}`)
    ])
  }
);

      } catch (e) {
        console.error(`Failed to notify admin ${admin.telegramId}:`, e);
      }
    }

    ctx.reply('✅ Your request has been sent for admin approval.', teacherMenu);
    ctx.scene.leave();

  } catch (err) {
    console.error('Error saving request:', err);
    ctx.reply('❌ Failed to submit request.');
    ctx.scene.leave();
  }
});

requestStudentsListScene.action('cancel_request_students_list', async (ctx) => {
  await ctx.answerCbQuery();
  await ctx.reply('❌ Request cancelled.', teacherMenu);
  ctx.scene.leave();
});
stage.register(requestStudentsListScene);

// Teacher Registration Start Scene - COMPLETE FIXED VERSION
const teacherRegisterStartScene = new Scenes.BaseScene('teacher_register_start_scene');

teacherRegisterStartScene.enter(async (ctx) => {
    try {
        // Enhanced check: Verify user is not already a teacher
        const existingTeacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (existingTeacher) {
            const message = `✅ You are already registered as a teacher!\n\n` +
                           `👤 Name: ${existingTeacher.name}\n` +
                           `🆔 Teacher ID: ${existingTeacher.teacherId}\n\n` +
                           `Use the "🔐 Teacher Login" option to access your account.`;
            ctx.reply(message, teacherMenu);
            return ctx.scene.leave();
        }
        
        // Check if user is already a teacher in user collection
        const user = await getUserById(ctx.from.id);
        if (user && user.role === 'teacher') {
            ctx.reply('✅ You are already registered as a teacher! Use the "🔐 Teacher Login" option.', teacherMenu);
            return ctx.scene.leave();
        }

        // Check if already has pending registration
        const existingOTP = await OTP.findOne({ telegramId: ctx.from.id });
        if (existingOTP && !isOTPExpired(existingOTP.expiresAt) && !existingOTP.verified) {
            ctx.reply('📧 You already have a pending registration. Please check your messages for the OTP.');
            return ctx.scene.leave();
        }

        // Generate and send OTP to admins
        const otp = generateOTP();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes expiration

        // Delete any existing OTP
        await OTP.deleteOne({ telegramId: ctx.from.id });

        // Save new OTP
        const newOTP = new OTP({
            telegramId: ctx.from.id,
            otp: otp,
            expiresAt: expiresAt,
            code: otp // Set code to the same value as otp to avoid null
        });
        await newOTP.save();

        // Notify all admins
        const admins = await getAdmins();
        let notifiedAdmins = 0;

        for (const admin of admins) {
            try {
                await ctx.telegram.sendMessage(
                    admin.telegramId,
                    `🔐 *New Teacher Registration Request:*\n\n` +
                    `👤 Telegram User: ${ctx.from.first_name || 'Unknown'} ${ctx.from.last_name || ''}\n` +
                    `📱 Username: @${ctx.from.username || 'N/A'}\n` +
                    `🆔 Telegram ID: ${ctx.from.id}\n\n` +
                    `🔢 *OTP Code:* ${otp}\n` +
                    `⏰ Expires: ${expiresAt.toLocaleTimeString()}`,
                    { parse_mode: 'Markdown' }
                );
                notifiedAdmins++;
            } catch (error) {
                console.error(`Failed to notify admin ${admin.telegramId}:`, error);
            }
        }

        if (notifiedAdmins > 0) {
            ctx.reply(
                '📧 A verification code has been sent to administrators.\n\n' +
                'Please wait for an admin to provide you with the 6-digit verification code, then enter it below:',
                Markup.keyboard([['❌ Cancel Registration']]).resize()
            );
        } else {
            ctx.reply('❌ No administrators are available to process your registration. Please try again later.');
            await OTP.deleteOne({ telegramId: ctx.from.id });
            ctx.scene.leave();
        }
    } catch (error) {
        console.error('Error in teacher registration start:', error);
        ctx.reply('❌ An error occurred while starting registration. Please try again.');
        ctx.scene.leave();
    }
});

teacherRegisterStartScene.on('text', async (ctx) => {
    const text = ctx.message.text.trim();

    if (text === '❌ Cancel Registration') {
        await OTP.deleteOne({ telegramId: ctx.from.id });
        ctx.reply('❌ Registration cancelled.', Markup.removeKeyboard());
        return ctx.scene.leave();
    }

    // Check if it's a 6-digit number
    if (!/^\d{6}$/.test(text)) {
        ctx.reply('❌ Please enter a valid 6-digit verification code.');
        return;
    }

    const otpRecord = await OTP.findOne({ telegramId: ctx.from.id });
    
    if (!otpRecord) {
        ctx.reply('❌ No registration request found. Please start over.');
        return ctx.scene.leave();
    }

    if (isOTPExpired(otpRecord.expiresAt)) {
        ctx.reply('❌ Verification code has expired. Please start registration again.');
        await OTP.deleteOne({ telegramId: ctx.from.id });
        return ctx.scene.leave();
    }

    if (otpRecord.attempts >= 3) {
        ctx.reply('❌ Too many failed attempts. Please start registration again.');
        await OTP.deleteOne({ telegramId: ctx.from.id });
        return ctx.scene.leave();
    }
// Teacher Register Start Scene - Add action handlers
teacherRegisterStartScene.action('cancel_registration', async (ctx) => {
    await ctx.answerCbQuery();
    await OTP.deleteOne({ telegramId: ctx.from.id });
    ctx.reply('❌ Registration cancelled.', Markup.removeKeyboard());
    ctx.scene.leave();
});

// Teacher Register Name Scene - Add action handlers
teacherRegisterNameScene.action('confirm_registration', async (ctx) => {
    await ctx.answerCbQuery();
    // Handle confirmation logic
});

teacherRegisterNameScene.action('cancel_registration_name', async (ctx) => {
    await ctx.answerCbQuery();
    await OTP.deleteOne({ telegramId: ctx.from.id });
    ctx.reply('❌ Registration cancelled.', Markup.removeKeyboard());
    ctx.scene.leave();
});
    if (text !== otpRecord.otp) {
        otpRecord.attempts += 1;
        await otpRecord.save();
        
        const remainingAttempts = 3 - otpRecord.attempts;
        ctx.reply(`❌ Invalid verification code. ${remainingAttempts} attempt(s) remaining.`);
        return;
    }

    // OTP is correct
    otpRecord.verified = true;
    await otpRecord.save();

    // FINAL CHECK: Ensure no duplicate teacher exists before proceeding
    const existingTeacher = await Teacher.findOne({ telegramId: ctx.from.id });
    if (existingTeacher) {
        const message = `✅ You are already registered as a teacher!\n\n` +
                       `👤 Name: ${existingTeacher.name}\n` +
                       `🆔 Teacher ID: ${existingTeacher.teacherId}\n\n` +
                       `Use the "🔐 Teacher Login" option to access your account.`;
        ctx.reply(message, teacherMenu);
        
        // Clean up OTP
        await OTP.deleteOne({ telegramId: ctx.from.id });
        
        return ctx.scene.leave();
    }

    ctx.reply('✅ Verification successful! Please enter your full name:');
    ctx.scene.enter('teacher_register_name_scene');
});

// Register the scene
stage.register(teacherRegisterStartScene);

// Teacher Register Name Scene - FIXED VERSION
// Teacher Register Name Scene - FIXED VERSION with duplicate protection
const teacherRegisterNameScene = new Scenes.BaseScene('teacher_register_name_scene');

teacherRegisterNameScene.enter(async (ctx) => {
    // Check if user is already a teacher before proceeding
    const existingTeacher = await Teacher.findOne({ telegramId: ctx.from.id });
    if (existingTeacher) {
        ctx.reply('✅ You are already registered as a teacher!', teacherMenu);
        return ctx.scene.leave();
    }
    
    // Check if user already has teacher role
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        ctx.reply('✅ You are already registered as a teacher!', teacherMenu);
        return ctx.scene.leave();
    }
    
    ctx.reply('👤 Please enter your full name:');
});
teacherRegisterNameScene.on('text', async (ctx) => {
    const text = ctx.message.text.trim();
    
    // Handle confirmation/cancellation if we're in that state
    if (ctx.session.waitingForConfirmation) {
        if (text === 'CONFIRM') {
            const name = ctx.session.teacherName;
            const password = ctx.session.tempPassword;
            
            try {
                // FINAL CHECK: Ensure no duplicate teacher exists
                const existingTeacher = await Teacher.findOne({ telegramId: ctx.from.id });
                if (existingTeacher) {
                    ctx.reply('✅ You are already registered as a teacher!', teacherMenu);
                    
                    // Clean up OTP
                    await OTP.deleteOne({ telegramId: ctx.from.id });
                    
                    // Clear session
                    delete ctx.session.teacherName;
                    delete ctx.session.tempPassword;
                    delete ctx.session.waitingForConfirmation;
                    
                    return ctx.scene.leave();
                }
                
                // Generate unique teacher ID
                const teacherId = await generateUniqueTeacherId();
                
                // Create teacher record
                const newTeacher = new Teacher({
                    teacherId: teacherId,
                    name: name,
                    telegramId: ctx.from.id,
                    subjects: [],
                    pendingSubjects: []
                });
                await newTeacher.save();
                
                // Create login record with hashed password
                const hashedPassword = hashPassword(password);
                const teacherLogin = new TeacherLogin({
                    teacherId: teacherId,
                    password: hashedPassword
                });
                await teacherLogin.save();
                
                // Create/update user record
                let user = await getUserById(ctx.from.id);
                if (user) {
                    user.role = 'teacher';
                    user.name = name;
                    await user.save();
                } else {
                    user = new User({
                        telegramId: ctx.from.id,
                        username: ctx.from.username || '',
                        name: name,
                        role: 'teacher'
                    });
                    await user.save();
                }
                
                // Clean up OTP
                await OTP.deleteOne({ telegramId: ctx.from.id });
                
                // Clear session
                delete ctx.session.teacherName;
                delete ctx.session.tempPassword;
                delete ctx.session.waitingForConfirmation;
                
                ctx.replyWithMarkdown(
                    `✅ *Registration Successful!*\n\n` +
                    `👤 Name: ${name}\n` +
                    `🆔 Teacher ID: ${teacherId}\n` +
                    `🔐 Password: ${password}\n\n` +
                    `_Please save your Teacher ID and Password in a secure place._`,
                    await getLoginMenu(ctx.from.id)
                );
                
            } catch (error) {
                // Enhanced error handling for duplicate key and other errors
                if (error.code === 11000) {
                    ctx.reply('✅ You are already registered as a teacher!', teacherMenu);
                } else {
                    console.error('Error completing teacher registration:', error);
                    ctx.reply('❌ An error occurred during registration. Please try again.');
                }
                
                // Clean up regardless of error
                await OTP.deleteOne({ telegramId: ctx.from.id });
                delete ctx.session.teacherName;
                delete ctx.session.tempPassword;
                delete ctx.session.waitingForConfirmation;
            }
            
            ctx.scene.leave();
            return;
        } 
        else if (text === 'CANCEL') {
            await OTP.deleteOne({ telegramId: ctx.from.id });
            delete ctx.session.teacherName;
            delete ctx.session.tempPassword;
            delete ctx.session.waitingForConfirmation;
            
            ctx.reply('❌ Registration cancelled.', Markup.removeKeyboard());
            ctx.scene.leave();
            return;
        }
        else {
            // If they type something else while waiting for confirmation
            ctx.reply('Please type "CONFIRM" to complete registration or "CANCEL" to abort:');
            return;
        }
    }
    
    // This is the name input handling (original code)
    if (!isValidName(text)) {
        ctx.reply('❌ Invalid name. Please enter a valid name (1-100 characters).');
        return;
    }

    ctx.session.teacherName = text;
    
    // Generate a 6-digit password
    const password = generatePassword();
    ctx.session.tempPassword = password;
    ctx.session.waitingForConfirmation = true;
    
    ctx.reply(
        `🔐 Your auto-generated password is: ${password}\n\n` +
        'Please save this password securely. You will need it to log in.\n\n' +
        'Type "CONFIRM" to complete registration or "CANCEL" to abort:',
        Markup.keyboard([['CONFIRM'], ['CANCEL']]).resize()
    );
});

// Register the scene
stage.register(teacherRegisterNameScene);
// Register the scenes
stage.register(teacherRegisterStartScene);

// Teacher Login Scene
        
        // Verify password

// Teacher Login Scene - Fixed to properly set user role
const teacherLoginScene = new Scenes.BaseScene('teacher_login_scene');

teacherLoginScene.enter((ctx) => {
    ctx.reply(
        '🔐 Teacher Login\n\n' +
        'Please enter your Teacher ID:',
        Markup.keyboard([['❌ Cancel Login']]).resize()
    );
});

teacherLoginScene.on('text', async (ctx) => {
    const text = ctx.message.text.trim();
    
    if (text === '❌ Cancel Login') {
        ctx.reply('❌ Login cancelled.', loginMenu);
        return ctx.scene.leave();
    }
    
    if (!ctx.session.loginState) {
        // First step: Teacher ID
        if (!isValidTeacherId(text)) {
            ctx.reply('❌ Invalid Teacher ID format. Please enter a valid Teacher ID (e.g., TE1234).');
            return;
        }
        
        const teacher = await Teacher.findOne({ teacherId: text });
        if (!teacher) {
            ctx.reply('❌ Teacher ID not found. Please check and try again.');
            return;
        }
        
        ctx.session.loginState = 'password';
        ctx.session.loginTeacherId = text;
        ctx.reply('Please enter your password:');
    } else if (ctx.session.loginState === 'password') {
        // Second step: Password
        const teacherId = ctx.session.loginTeacherId;
        const password = text;
        
        const teacherLogin = await TeacherLogin.findOne({ teacherId });
        if (!teacherLogin) {
            ctx.reply('❌ Login credentials not found. Please contact an administrator.');
            delete ctx.session.loginState;
            delete ctx.session.loginTeacherId;
            return ctx.scene.leave();
        }
        
        // Check if account is locked
        if (isAccountLocked(teacherLogin.lockedUntil)) {
            const lockTime = Math.ceil((teacherLogin.lockedUntil - new Date()) / 60000); // minutes
            ctx.reply(`❌ Account temporarily locked. Try again in ${lockTime} minutes.`);
            delete ctx.session.loginState;
            delete ctx.session.loginTeacherId;
            return ctx.scene.leave();
        }
             // Teacher Login Scene - Add these action handlers
teacherLoginScene.action('cancel_login', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Login cancelled.', loginMenu);
    ctx.scene.leave();
});

teacherLoginScene.on('text', async (ctx) => {
    const text = ctx.message.text.trim();
    
    if (text === '❌ Cancel Login') {
        ctx.reply('❌ Login cancelled.', loginMenu);
        return ctx.scene.leave();
    }
    
    // ... rest of your existing login logic
});
        // Verify password
        if (!verifyPassword(password, teacherLogin.password)) {
            teacherLogin.loginAttempts += 1;
            
            // Lock account after 3 failed attempts for 15 minutes
            if (teacherLogin.loginAttempts >= 3) {
                teacherLogin.lockedUntil = new Date(Date.now() + 15 * 60 * 1000);
                teacherLogin.loginAttempts = 0;
                await teacherLogin.save();
                
                ctx.reply('❌ Too many failed attempts. Account locked for 15 minutes.');
            } else {
                const remainingAttempts = 3 - teacherLogin.loginAttempts;
                await teacherLogin.save();
                ctx.reply(`❌ Incorrect password. ${remainingAttempts} attempt(s) remaining.`);
            }
            
            return;
        }
        
        // Successful login
        teacherLogin.loginAttempts = 0;
        teacherLogin.lockedUntil = null;
        teacherLogin.lastLogin = new Date();
        await teacherLogin.save();
        


        // ✅ CRITICAL FIX: Update teacher telegramId if different
        const teacher = await Teacher.findOne({ teacherId });
        if (teacher) {
            // Update telegramId if it's different or missing
            if (teacher.telegramId !== ctx.from.id) {
                teacher.telegramId = ctx.from.id;
                await teacher.save();
            }
            
            // ✅ CRITICAL FIX: Ensure user record has correct role
            let user = await getUserById(ctx.from.id);
            if (user) {
                user.role = 'teacher';
                user.name = teacher.name; // Update name if changed
                if (teacher.subjects) {
                    user.subjects = teacher.subjects;
                }
                await user.save();
            } else {
                // Create new user record if it doesn't exist
                user = new User({
                    telegramId: ctx.from.id,
                    username: ctx.from.username || '',
                    name: teacher.name,
                    role: 'teacher',
                    subjects: teacher.subjects || []
                });
                await user.save();
            }
        }
        
        delete ctx.session.loginState;
        delete ctx.session.loginTeacherId;
        
        ctx.reply('✅ Login successful!', teacherMenu);
        ctx.scene.leave();
    }


});


// Register the login scene
stage.register(teacherLoginScene);

// --- Teacher Contact Admin Scene ---
const teacherContactAdminScene = new Scenes.BaseScene('teacher_contact_admin_scene');

teacherContactAdminScene.enter(async (ctx) => {
    try {
        const admins = await getAdmins();
        
        if (admins.length === 0) {
            ctx.reply('❌ No admins found to contact.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create admin selection buttons
        const adminButtons = admins.map(admin => [
            Markup.button.callback(
                `${admin.name} (ID: ${admin.telegramId})`,
                `select_admin_${admin.telegramId}`
            )
        ]);
        
        adminButtons.push([Markup.button.callback('❌ Cancel', 'cancel_contact_admin')]);

        ctx.reply('👑 Select an admin to contact:', Markup.inlineKeyboard(adminButtons));

    } catch (error) {
        console.error('Error in teacher contact admin scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle admin selection
teacherContactAdminScene.action(/^select_admin_(\d+)$/, async (ctx) => {
    const adminId = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        const admin = await getUserById(adminId);
        if (!admin) {
            ctx.reply('❌ Admin not found.', teacherMenu);
            return ctx.scene.leave();
        }
        
        // Store admin info in session
        ctx.session.contactAdminInfo = {
            adminId: adminId,
            adminName: admin.name
        };

        ctx.reply(
            `📬 You are now messaging **${admin.name}**.\n\n` +
            `Please send your message (text, photo, video, document, audio, or voice):`,
            Markup.keyboard([['❌ Cancel']]).resize()
        );

    } catch (error) {
        console.error('Error selecting admin:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle cancellation
teacherContactAdminScene.action('cancel_contact_admin', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Contact admin cancelled.', teacherMenu);
    ctx.scene.leave();
});

// Handle text cancellation
teacherContactAdminScene.hears('❌ Cancel', async (ctx) => {
    ctx.reply('❌ Contact admin cancelled.', teacherMenu);
    ctx.scene.leave();
});
teacherContactAdminScene.on(['text', 'photo', 'video', 'document', 'audio', 'voice'], async (ctx) => {
    const contactInfo = ctx.session.contactAdminInfo;
    
    if (!contactInfo) {
        ctx.reply('❌ No admin selected. Please start over.', teacherMenu);
        return ctx.scene.leave();
    }

    const { adminId, adminName } = contactInfo;

    let success = false;
    let errorMessage = '';

    try {
        // Get rich teacher information
        const teacherInfoRich = await getRichTeacherInfo(ctx.from.id);
        if (!teacherInfoRich) {
            ctx.reply('❌ Could not retrieve your teacher information.', teacherMenu);
            delete ctx.session.contactAdminInfo;
            return ctx.scene.leave();
        }

        // Create enhanced teacher info header
        const teacherInfo = `
🧑‍🏫 *Teacher Contact Request:*
━━━━━━━━━━━━━━━━━━━━
• 👤 *Name:* ${teacherInfoRich.name}
• 🆔 *Teacher ID:* ${teacherInfoRich.teacherId}
• 📞 *Telegram ID:* ${teacherInfoRich.telegramId}
${teacherInfoRich.username ? `• 👤 *Username:* @${teacherInfoRich.username}\n` : ''}

📚 *Teaching Subjects:*
${teacherInfoRich.subjects.map(subj => `  • ${subj}`).join('\n') || '  • No subjects assigned'}

📊 *Statistics:*
• 👥 Total Students: ${teacherInfoRich.studentCount}
• 🏆 Top Subject: ${teacherInfoRich.subjectStats[0]?._id || 'N/A'} (${teacherInfoRich.subjectStats[0]?.studentCount || 0} students)

📅 *Registered:* ${new Date(teacherInfoRich.registrationDate).toLocaleDateString()}
━━━━━━━━━━━━━━━━━━━━

💬 *Message from Teacher:*
`;

        // Send appropriate message based on content type
        if (ctx.message.text) {
            // Text message
            await ctx.telegram.sendMessage(
                adminId,
                teacherInfo + ctx.message.text,
                { parse_mode: 'Markdown' }
            );
            success = true;
        } 
        else if (ctx.message.photo) {
            // Photo with caption and teacher info
            const photo = ctx.message.photo[ctx.message.photo.length - 1];
            const caption = ctx.message.caption 
                ? teacherInfo + ctx.message.caption
                : teacherInfo + '📸 Photo message';
            
            await ctx.telegram.sendPhoto(
                adminId,
                photo.file_id,
                { caption, parse_mode: 'Markdown' }
            );
            success = true;
        }
        else if (ctx.message.video) {
            // Video with caption and teacher info
            const caption = ctx.message.caption 
                ? teacherInfo + ctx.message.caption
                : teacherInfo + '🎥 Video message';
            
            await ctx.telegram.sendVideo(
                adminId,
                ctx.message.video.file_id,
                { caption, parse_mode: 'Markdown' }
            );
            success = true;
        }
        else if (ctx.message.document) {
            // Document with caption and teacher info
            const caption = ctx.message.caption 
                ? teacherInfo + ctx.message.caption
                : teacherInfo + '📄 Document message';
            
            await ctx.telegram.sendDocument(
                adminId,
                ctx.message.document.file_id,
                { caption, parse_mode: 'Markdown' }
            );
            success = true;
        }
        else if (ctx.message.audio) {
            // Audio with caption and teacher info
            const caption = ctx.message.caption 
                ? teacherInfo + ctx.message.caption
                : teacherInfo + '🎵 Audio message';
            
            await ctx.telegram.sendAudio(
                adminId,
                ctx.message.audio.file_id,
                { caption, parse_mode: 'Markdown' }
            );
            success = true;
        }
        else if (ctx.message.voice) {
            // Voice message with separate teacher info
            await ctx.telegram.sendVoice(
                adminId,
                ctx.message.voice.file_id
            );
            await ctx.telegram.sendMessage(
                adminId,
                teacherInfo + '🗣️ Voice message from teacher',
                { parse_mode: 'Markdown' }
            );
            success = true;
        }

        if (success) {
            ctx.replyWithMarkdown(
                `✅ *Message delivered to ${adminName}!*\n\n` +
                `👑 Admin: ${adminName}\n` +
                `📧 Status: ✅ Delivered\n` +
                `⏰ Time: ${new Date().toLocaleTimeString()}\n\n` +
                `_The admin can see your full teacher information below your message._`,
                teacherMenu
            );
        }

    } catch (error) {
        if (error.response?.error_code === 403) {
            errorMessage = '❌ Failed to send message. The admin may have blocked the bot.';
        } else {
            console.error('Error sending message to admin:', error);
            errorMessage = '❌ Failed to send message. Please try again later.';
        }
        ctx.reply(errorMessage, teacherMenu);
    } finally {
        // Clean up session
        delete ctx.session.contactAdminInfo;
        ctx.scene.leave();
    }
});
// Register the scene
stage.register(teacherContactAdminScene);
// View Students Scene
const viewStudentsScene = new Scenes.BaseScene('view_students_scene');

viewStudentsScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get all students grouped by subject
        const studentsBySubject = await TeacherStudent.aggregate([
            { $match: { teacherId: teacher.teacherId } },
            { $group: {
                _id: '$subject',
                students: { $push: { name: '$studentName', id: '$studentId', class: '$className' } },
                count: { $sum: 1 }
            }},
            { $sort: { _id: 1 } }
        ]);

        if (studentsBySubject.length === 0) {
            ctx.reply('❌ You have no students in your database.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = studentsBySubject.map(subject => [
            Markup.button.callback(
                `${subject._id} (${subject.count} students)`,
                `view_subject_${subject._id.replace(/ /g, '_')}`
            )
        ]);
        
        subjectButtons.push([Markup.button.callback('📊 View All Students', 'view_all_students')]);
        subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_view_students')]);

        let message = '👥 *Your Students by Subject:*\n\n';
        studentsBySubject.forEach(subject => {
            message += `📚 ${subject._id}: ${subject.count} students\n`;
        });

        message += `\n📊 Total: ${studentsBySubject.reduce((sum, sub) => sum + sub.count, 0)} students`;

        ctx.replyWithMarkdown(
            message,
            Markup.inlineKeyboard(subjectButtons)
        );

    } catch (error) {
        console.error('Error in view students scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject selection
viewStudentsScene.action(/^view_subject_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get students for this subject
        const students = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            subject: subject
        }).sort({ studentName: 1 });

        let message = `📚 *Students in ${subject}:*\n\n`;
        
        students.forEach((student, index) => {
            message += `${index + 1}. ${student.studentName}\n`;
            message += `   🆔 ID: ${student.studentId}\n`;
            message += `   🏫 Class: ${student.className}\n`;
            message += `   📅 Added: ${new Date(student.addedDate).toLocaleDateString()}\n\n`;
        });

        message += `📊 Total: ${students.length} students`;

        // Create action buttons
        const actionButtons = [
            [Markup.button.callback('📋 Export This List', `export_subject_${subject.replace(/ /g, '_')}`)],
            [Markup.button.callback('⬅️ Back to Subjects', 'back_to_subjects_view')],
            [Markup.button.callback('❌ Close', 'cancel_view_students')]
        ];

        ctx.replyWithMarkdown(message, Markup.inlineKeyboard(actionButtons));

    } catch (error) {
        console.error('Error viewing subject students:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle view all students
viewStudentsScene.action('view_all_students', async (ctx) => {
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get all students sorted by name
        const allStudents = await TeacherStudent.find({
            teacherId: teacher.teacherId
        }).sort({ studentName: 1 });

        // Group by first letter for organization
        const studentsByLetter = {};
        allStudents.forEach(student => {
            const firstLetter = student.studentName.charAt(0).toUpperCase();
            if (!studentsByLetter[firstLetter]) {
                studentsByLetter[firstLetter] = [];
            }
            studentsByLetter[firstLetter].push(student);
        });

        let message = '👥 *All Your Students:*\n\n';
        
        Object.keys(studentsByLetter).sort().forEach(letter => {
            message += `🔤 *${letter}:* ${studentsByLetter[letter].length} students\n`;
        });

        message += `\n📊 Total: ${allStudents.length} students\n\n`;
        message += 'Select a letter to view students:';

        // Create letter buttons
        const letterButtons = Object.keys(studentsByLetter).sort().map(letter => [
            Markup.button.callback(letter, `view_letter_${letter}`)
        ]);

        letterButtons.push([Markup.button.callback('📋 Export All', 'export_all_students')]);
        letterButtons.push([Markup.button.callback('⬅️ Back', 'back_to_subjects_view')]);
        letterButtons.push([Markup.button.callback('❌ Close', 'cancel_view_students')]);

        ctx.replyWithMarkdown(message, Markup.inlineKeyboard(letterButtons));

    } catch (error) {
        console.error('Error viewing all students:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle letter selection
viewStudentsScene.action(/^view_letter_(.+)$/, async (ctx) => {
    const letter = ctx.match[1];
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get students whose names start with this letter
        const students = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            studentName: { $regex: `^${letter}`, $options: 'i' }
        }).sort({ studentName: 1 });

        let message = `🔤 *Students starting with ${letter}:*\n\n`;
        
        students.forEach((student, index) => {
            message += `${index + 1}. ${student.studentName}\n`;
            message += `   🆔 ID: ${student.studentId}\n`;
            message += `   📚 Subject: ${student.subject}\n`;
            message += `   🏫 Class: ${student.className}\n\n`;
        });

        message += `📊 Total: ${students.length} students`;

        ctx.replyWithMarkdown(message, Markup.inlineKeyboard([
            [Markup.button.callback('⬅️ Back to Letters', 'view_all_students')],
            [Markup.button.callback('❌ Close', 'cancel_view_students')]
        ]));

    } catch (error) {
        console.error('Error viewing letter students:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle back actions
viewStudentsScene.action('back_to_subjects_view', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.reenter();
});

// Handle cancellation
viewStudentsScene.action('cancel_view_students', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ View students cancelled.', teacherMenu);
    ctx.scene.leave();
});

// Handle text cancellation
viewStudentsScene.hears('❌ Cancel', async (ctx) => {
    ctx.reply('❌ View students cancelled.', teacherMenu);
    ctx.scene.leave();
});
// View Uploaded Lists Scene
const viewUploadedListsScene = new Scenes.BaseScene('view_uploaded_lists_scene');

viewUploadedListsScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get all uploaded lists (class names) with detailed information
        const uploadedLists = await TeacherStudent.aggregate([
            { $match: { teacherId: teacher.teacherId } },
            { $group: {
                _id: '$className',
                studentCount: { $sum: 1 },
                subjectCount: { $addToSet: '$subject' },
                firstAdded: { $min: '$addedDate' },
                lastAdded: { $max: '$addedDate' }
            }},
            { $project: {
                className: '$_id',
                studentCount: 1,
                subjectCount: { $size: '$subjectCount' },
                dateRange: {
                    $concat: [
                        { $dateToString: { format: '%Y-%m-%d', date: '$firstAdded' } },
                        ' to ',
                        { $dateToString: { format: '%Y-%m-%d', date: '$lastAdded' } }
                    ]
                },
                durationDays: {
                    $divide: [
                        { $subtract: ['$lastAdded', '$firstAdded'] },
                        1000 * 60 * 60 * 24
                    ]
                }
            }},
            { $sort: { className: 1 } }
        ]);

        if (uploadedLists.length === 0) {
            ctx.reply('❌ You have no uploaded lists in your database.', teacherMenu);
            return ctx.scene.leave();
        }

        const totalStudents = uploadedLists.reduce((sum, list) => sum + list.studentCount, 0);

        let message = '📋 *Your Uploaded Lists:*\n\n';
        
        uploadedLists.forEach((list, index) => {
            message += `*${index + 1}. ${list.className}:*\n`;
            message += `   👥 Students: ${list.studentCount}\n`;
            message += `   📚 Subjects: ${list.subjectCount}\n`;
            message += `   📅 Period: ${list.dateRange}\n`;
            message += `   📆 Duration: ${Math.round(list.durationDays)} days\n\n`;
        });

        message += `📊 *Totals:*\n`;
        message += `• Lists: ${uploadedLists.length}\n`;
        message += `• Students: ${totalStudents}\n`;
        message += `• Average per list: ${Math.round(totalStudents / uploadedLists.length)} students`;

        // Create list selection buttons
        const listButtons = uploadedLists.map(list => [
            Markup.button.callback(
                `📋 ${list.className}`,
                `view_list_${list.className.replace(/ /g, '_')}`
            )
        ]);

        listButtons.push([Markup.button.callback('📊 List Statistics', 'view_list_stats')]);
        listButtons.push([Markup.button.callback('❌ Close', 'cancel_view_lists')]);

        ctx.replyWithMarkdown(
            message,
            Markup.inlineKeyboard(listButtons)
        );

    } catch (error) {
        console.error('Error in view uploaded lists scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle list selection
viewUploadedListsScene.action(/^view_list_(.+)$/, async (ctx) => {
    const className = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get detailed information about this list
        const listDetails = await TeacherStudent.aggregate([
            { $match: { teacherId: teacher.teacherId, className: className } },
            { $group: {
                _id: '$subject',
                studentCount: { $sum: 1 },
                studentNames: { $push: '$studentName' },
                firstAdded: { $min: '$addedDate' },
                lastAdded: { $max: '$addedDate' }
            }},
            { $sort: { _id: 1 } }
        ]);

        const totalStudents = listDetails.reduce((sum, subject) => sum + subject.studentCount, 0);

        let message = `📋 *List Details: ${className}*\n\n`;
        message += `📊 Total Students: ${totalStudents}\n`;
        message += `📚 Subjects: ${listDetails.length}\n\n`;
        
        message += '*Subjects in this list:*\n';
        listDetails.forEach((subject, index) => {
            message += `${index + 1}. *${subject._id}:* ${subject.studentCount} students\n`;
        });

        message += `\n📅 First added: ${new Date(listDetails[0].firstAdded).toLocaleDateString()}\n`;
        message += `📅 Last added: ${new Date(listDetails[0].lastAdded).toLocaleDateString()}\n`;
        message += `📆 Active for: ${Math.round((new Date(listDetails[0].lastAdded) - new Date(listDetails[0].firstAdded)) / (1000 * 60 * 60 * 24))} days`;

        // Create action buttons
        const actionButtons = [
            [Markup.button.callback('👀 View Students', `view_list_students_${className.replace(/ /g, '_')}`)],
            [Markup.button.callback('📋 Export List', `export_list_${className.replace(/ /g, '_')}`)],
            [Markup.button.callback('⬅️ Back to Lists', 'back_to_lists_view')],
            [Markup.button.callback('❌ Close', 'cancel_view_lists')]
        ];

        ctx.replyWithMarkdown(message, Markup.inlineKeyboard(actionButtons));

    } catch (error) {
        console.error('Error viewing list details:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle view list students
viewUploadedListsScene.action(/^view_list_students_(.+)$/, async (ctx) => {
    const className = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get students from this list
        const students = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            className: className
        }).sort({ studentName: 1 });

        // Group by subject
        const studentsBySubject = {};
        students.forEach(student => {
            if (!studentsBySubject[student.subject]) {
                studentsBySubject[student.subject] = [];
            }
            studentsBySubject[student.subject].push(student);
        });

        let message = `👥 *Students in ${className}:*\n\n`;
        
        Object.keys(studentsBySubject).sort().forEach(subject => {
            message += `📚 *${subject}:* ${studentsBySubject[subject].length} students\n`;
            
            // Show first 3 students from each subject
            studentsBySubject[subject].slice(0, 3).forEach((student, index) => {
                message += `   ${index + 1}. ${student.studentName} (${student.studentId})\n`;
            });
            
            if (studentsBySubject[subject].length > 3) {
                message += `   ... and ${studentsBySubject[subject].length - 3} more\n`;
            }
            message += '\n';
        });

        message += `📊 Total: ${students.length} students`;

        ctx.replyWithMarkdown(message, Markup.inlineKeyboard([
            [Markup.button.callback('⬅️ Back to List', `view_list_${className.replace(/ /g, '_')}`)],
            [Markup.button.callback('❌ Close', 'cancel_view_lists')]
        ]));

    } catch (error) {
        console.error('Error viewing list students:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle list statistics
viewUploadedListsScene.action('view_list_stats', async (ctx) => {
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get comprehensive statistics
        const stats = await TeacherStudent.aggregate([
            { $match: { teacherId: teacher.teacherId } },
            { $group: {
                _id: null,
                totalLists: { $addToSet: '$className' },
                totalStudents: { $sum: 1 },
                totalSubjects: { $addToSet: '$subject' },
                avgStudentsPerList: { $avg: '$studentCount' },
                earliestDate: { $min: '$addedDate' },
                latestDate: { $max: '$addedDate' }
            }},
            { $project: {
                totalLists: { $size: '$totalLists' },
                totalStudents: 1,
                totalSubjects: { $size: '$totalSubjects' },
                avgStudentsPerList: { $round: ['$avgStudentsPerList', 1] },
                durationDays: {
                    $divide: [
                        { $subtract: ['$latestDate', '$earliestDate'] },
                        1000 * 60 * 60 * 24
                    ]
                }
            }}
        ]);

        const stat = stats[0];

        let message = '📊 *List Statistics Summary:*\n\n';
        message += `📋 Total Lists: ${stat.totalLists}\n`;
        message += `👥 Total Students: ${stat.totalStudents}\n`;
        message += `📚 Total Subjects: ${stat.totalSubjects}\n`;
        message += `📈 Avg Students/List: ${stat.avgStudentsPerList}\n`;
        message += `📅 Activity Period: ${Math.round(stat.durationDays)} days\n`;
        message += `📆 From: ${new Date(stat.earliestDate).toLocaleDateString()}\n`;
        message += `📆 To: ${new Date(stat.latestDate).toLocaleDateString()}\n\n`;
        message += `🏆 Most active period: ${Math.round(stat.durationDays / 30)} months`;

        ctx.replyWithMarkdown(message, Markup.inlineKeyboard([
            [Markup.button.callback('⬅️ Back to Lists', 'back_to_lists_view')],
            [Markup.button.callback('❌ Close', 'cancel_view_lists')]
        ]));

    } catch (error) {
        console.error('Error viewing statistics:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle back actions
viewUploadedListsScene.action('back_to_lists_view', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.reenter();
});

// Handle cancellation
viewUploadedListsScene.action('cancel_view_lists', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ View lists cancelled.', teacherMenu);
    ctx.scene.leave();
});

// Handle text cancellation
viewUploadedListsScene.hears('❌ Cancel', async (ctx) => {
    ctx.reply('❌ View lists cancelled.', teacherMenu);
    ctx.scene.leave();
});
// Register the scenes
stage.register(viewStudentsScene);
stage.register(viewUploadedListsScene);
// Teacher My Students Scene - Updated version
const teacherMyStudentsScene = new Scenes.BaseScene('teacher_my_students_scene');

teacherMyStudentsScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher) {
            ctx.reply('❌ Teacher profile not found.', teacherMenu);
            return ctx.scene.leave();
        }

        // Check if teacher has any students
        const studentCount = await TeacherStudent.countDocuments({ teacherId: teacher.teacherId });
        
        if (studentCount === 0) {
            ctx.reply('❌ You have no students in your database.', teacherMenu);
            return ctx.scene.leave();
        }

        // Get unique uploaded lists (class names) from teacher's students
        const uploadedLists = await TeacherStudent.aggregate([
            { $match: { teacherId: teacher.teacherId } },
            { $group: { 
                _id: '$className',
                studentCount: { $sum: 1 },
                subjects: { $addToSet: '$subject' }
            }},
            { $sort: { _id: 1 } }
        ]);

        // Create action buttons - REMOVED THE PLACEHOLDER MESSAGES
        const actionButtons = [
            [Markup.button.callback('👀 View My Students', 'view_my_students')],
            [Markup.button.callback('📋 View Uploaded Lists', 'view_uploaded_lists')],
            [Markup.button.callback('🗑️ Remove Student', 'remove_student_option')],
            [Markup.button.callback('🗑️ Remove Uploaded List', 'remove_uploaded_list')],
            [Markup.button.callback('❌ Cancel', 'back_to_teacher_menu')]
        ];

        ctx.reply(
            '📚 *My Students Management*\n\n' +
            `Total Students: ${studentCount}\n` +
            `Uploaded Lists: ${uploadedLists.length}\n\n` +
            'Select an option:',
            Markup.inlineKeyboard(actionButtons)
        );

    } catch (error) {
        console.error('Error in teacher my students scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// ACTION HANDLERS - UPDATED TO CALL THE ACTUAL SCENES
teacherMyStudentsScene.action('view_my_students', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('view_students_scene'); // Now calls the actual scene
});

teacherMyStudentsScene.action('view_uploaded_lists', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('view_uploaded_lists_scene'); // Now calls the actual scene
});

teacherMyStudentsScene.action('remove_student_option', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('teacher_remove_student_scene');
});

teacherMyStudentsScene.action('remove_uploaded_list', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('remove_uploaded_list_scene');
});

teacherMyStudentsScene.action('back_to_teacher_menu', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('⬅️ Returning to teacher menu.', teacherMenu);
    ctx.scene.leave();
});

// Handle text cancellation
teacherMyStudentsScene.hears('❌ Cancel', async (ctx) => {
    ctx.reply('❌ Operation cancelled.', teacherMenu);
    ctx.scene.leave();
});
stage.register(teacherMyStudentsScene);
// Remove Uploaded List Scene
const removeUploadedListScene = new Scenes.BaseScene('remove_uploaded_list_scene');

removeUploadedListScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get unique uploaded lists (class names) with counts and subjects
        const uploadedLists = await TeacherStudent.aggregate([
            { $match: { teacherId: teacher.teacherId } },
            { $group: { 
                _id: '$className',
                studentCount: { $sum: 1 },
                subjects: { $addToSet: '$subject' },
                firstAdded: { $min: '$addedDate' },
                lastAdded: { $max: '$addedDate' }
            }},
            { $sort: { _id: 1 } }
        ]);

        if (uploadedLists.length === 0) {
            ctx.reply('❌ You have no uploaded lists in your database.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create list selection buttons with rich information
        const listButtons = uploadedLists.map(list => [
            Markup.button.callback(
                `📋 ${list._id} (${list.studentCount} students)`,
                `select_list_${list._id.replace(/ /g, '_')}`
            )
        ]);
        
        listButtons.push([Markup.button.callback('❌ Cancel', 'cancel_remove_list')]);

        let message = '📚 *Your Uploaded Lists:*\n\n';
        uploadedLists.forEach(list => {
            message += `• ${list._id}: ${list.studentCount} students, ${list.subjects.length} subjects\n`;
        });

        ctx.replyWithMarkdown(
            message + '\nSelect a list to remove:',
            Markup.inlineKeyboard(listButtons)
        );

    } catch (error) {
        console.error('Error in remove uploaded list scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle list selection
removeUploadedListScene.action(/^select_list_(.+)$/, async (ctx) => {
    const className = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get detailed information about the list
        const listDetails = await TeacherStudent.aggregate([
            { $match: { teacherId: teacher.teacherId, className: className } },
            { $group: {
                _id: '$subject',
                studentCount: { $sum: 1 },
                firstAdded: { $min: '$addedDate' },
                lastAdded: { $max: '$addedDate' }
            }},
            { $sort: { _id: 1 } }
        ]);

        const totalStudents = listDetails.reduce((sum, subject) => sum + subject.studentCount, 0);
        
        let message = `📋 *List Details: ${className}*\n\n`;
        message += `📊 Total Students: ${totalStudents}\n`;
        message += `📚 Subjects: ${listDetails.length}\n\n`;
        
        message += '*Subjects in this list:*\n';
        listDetails.forEach((subject, index) => {
            message += `${index + 1}. ${subject._id}: ${subject.studentCount} students\n`;
        });

        message += `\n📅 First added: ${new Date(listDetails[0]?.firstAdded).toLocaleDateString()}\n`;
        message += `📅 Last added: ${new Date(listDetails[0]?.lastAdded).toLocaleDateString()}\n\n`;
        message += '⚠️ *This will remove ALL students from this list across all subjects!*';

        ctx.replyWithMarkdown(
            message,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Confirm Remove Entire List', `confirm_remove_list_${className.replace(/ /g, '_')}`)],
                [Markup.button.callback('📋 Remove by Subject', `remove_by_subject_${className.replace(/ /g, '_')}`)],
                [Markup.button.callback('❌ Cancel', 'cancel_remove_list')]
            ])
        );

    } catch (error) {
        console.error('Error selecting list:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle entire list removal confirmation
removeUploadedListScene.action(/^confirm_remove_list_(.+)$/, async (ctx) => {
    const className = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get count before deletion for confirmation
        const deleteResult = await TeacherStudent.deleteMany({
            teacherId: teacher.teacherId,
            className: className
        });

        ctx.replyWithMarkdown(
            `✅ *Successfully removed entire list!*\n\n` +
            `📋 List: ${className}\n` +
            `👥 Students removed: ${deleteResult.deletedCount}\n` +
            `🧑‍🏫 Teacher: ${teacher.name}\n` +
            `⏰ Removed: ${new Date().toLocaleString()}`,
            teacherMenu
        );

    } catch (error) {
        console.error('Error removing list:', error);
        ctx.reply('❌ An error occurred while removing the list.', teacherMenu);
    }
    
    ctx.scene.leave();
});

// Handle remove by subject option
removeUploadedListScene.action(/^remove_by_subject_(.+)$/, async (ctx) => {
    const className = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get subjects for this class
        const subjects = await TeacherStudent.aggregate([
            { $match: { teacherId: teacher.teacherId, className: className } },
            { $group: {
                _id: '$subject',
                studentCount: { $sum: 1 }
            }},
            { $sort: { _id: 1 } }
        ]);

        // Create subject selection buttons
        const subjectButtons = subjects.map(subject => [
            Markup.button.callback(
                `📚 ${subject._id} (${subject.studentCount} students)`,
                `remove_subject_from_list_${className.replace(/ /g, '_')}_${subject._id.replace(/ /g, '_')}`
            )
        ]);
        
        subjectButtons.push([Markup.button.callback('⬅️ Back to List', `back_to_list_${className.replace(/ /g, '_')}`)]);
        subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_remove_list')]);

        ctx.reply(
            `📚 Select a subject to remove from ${className}:`,
            Markup.inlineKeyboard(subjectButtons)
        );

    } catch (error) {
        console.error('Error selecting subject:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject removal from list
removeUploadedListScene.action(/^remove_subject_from_list_(.+)_(.+)$/, async (ctx) => {
    const className = ctx.match[1].replace(/_/g, ' ');
    const subject = ctx.match[2].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get count before deletion
        const countBefore = await TeacherStudent.countDocuments({
            teacherId: teacher.teacherId,
            className: className,
            subject: subject
        });

        const deleteResult = await TeacherStudent.deleteMany({
            teacherId: teacher.teacherId,
            className: className,
            subject: subject
        });

        ctx.replyWithMarkdown(
            `✅ *Successfully removed subject from list!*\n\n` +
            `📋 List: ${className}\n` +
            `📚 Subject: ${subject}\n` +
            `👥 Students removed: ${deleteResult.deletedCount}\n` +
            `🧑‍🏫 Teacher: ${teacher.name}\n` +
            `⏰ Removed: ${new Date().toLocaleString()}`,
            teacherMenu
        );

    } catch (error) {
        console.error('Error removing subject from list:', error);
        ctx.reply('❌ An error occurred while removing the subject.', teacherMenu);
    }
    
    ctx.scene.leave();
});

// Handle back to list
removeUploadedListScene.action(/^back_to_list_(.+)$/, async (ctx) => {
    const className = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();
    ctx.scene.reenter(); // Go back to list selection
});

// Handle cancellation
removeUploadedListScene.action('cancel_remove_list', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ List removal cancelled.', teacherMenu);
    ctx.scene.leave();
});

// Handle text cancellation
removeUploadedListScene.hears('❌ Cancel', async (ctx) => {
    ctx.reply('❌ List removal cancelled.', teacherMenu);
    ctx.scene.leave();
});

// Register the scene
stage.register(removeUploadedListScene);

// Teacher Export Grades Scene
const teacherExportGradesScene = new Scenes.BaseScene('teacher_export_grades_scene');

teacherExportGradesScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no subjects assigned.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(subject, `export_grades_${subject.replace(/ /g, '_')}`)]
        );
        
        // Add cancel button
        subjectButtons.push([Markup.button.callback('❌ Cancel Export', 'cancel_export_grades')]);

        ctx.reply('📚 Select a subject to export grades from:', Markup.inlineKeyboard(subjectButtons));

    } catch (error) {
        console.error('Error in export grades scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject selection
teacherExportGradesScene.action(/^export_grades_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get all grades for this subject
        const grades = await Grade.find({
            teacherId: teacher.teacherId,
            subject: subject
        }).sort({ studentName: 1, date: -1 });

        if (grades.length === 0) {
            ctx.reply(`❌ No grades found for ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Group grades by student
        const gradesByStudent = {};
        grades.forEach(grade => {
            if (!gradesByStudent[grade.studentId]) {
                gradesByStudent[grade.studentId] = {
                    studentName: grade.studentName,
                    grades: []
                };
            }
            gradesByStudent[grade.studentId].grades.push(grade);
        });

        // Generate the grade report
        const reportContent = generateGradeReport(subject, teacher.name, gradesByStudent);
        
        // Create temporary file
        const tempDir = './temp_exports';
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        
        const fileName = `grades_${subject.replace(/ /g, '_')}_${new Date().toISOString().split('T')[0]}.txt`;
        const filePath = path.join(tempDir, fileName);
        
        fs.writeFileSync(filePath, reportContent);

        // Send the file
        await ctx.replyWithDocument({
            source: filePath,
            filename: fileName,
            caption: `📊 Grade report for ${subject} (${grades.length} grades)`
        });

        // Clean up
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }

        ctx.reply('✅ Grade export completed!', teacherMenu);

    } catch (error) {
        console.error('Error exporting grades:', error);
        ctx.reply('❌ An error occurred while exporting grades.', teacherMenu);
    }
    
    ctx.scene.leave();
});

// Handle cancellation
teacherExportGradesScene.action('cancel_export_grades', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Grade export cancelled.', teacherMenu);
    ctx.scene.leave();
});

// Handle text cancellation
teacherExportGradesScene.hears('❌ Cancel Export', async (ctx) => {
    ctx.reply('❌ Grade export cancelled.', teacherMenu);
    ctx.scene.leave();
});

// Add this to the export grades scene for multiple format options
teacherExportGradesScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no subjects assigned.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(subject, `export_subject_${subject.replace(/ /g, '_')}`)]
        );
        
        // Add cancel button
        subjectButtons.push([Markup.button.callback('❌ Cancel Export', 'cancel_export_grades')]);

        ctx.reply('📚 Select a subject to export grades from:', Markup.inlineKeyboard(subjectButtons));

    } catch (error) {
        console.error('Error in export grades scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Update the subject selection handler to include format options
teacherExportGradesScene.action(/^export_subject_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    // Store selected subject
    ctx.session.exportSubject = subject;

    // Ask for format selection
    ctx.reply(
        `📊 Select export format for ${subject}:`,
        Markup.inlineKeyboard([
            [Markup.button.callback('📝 Text Report', `export_format_text_${subject.replace(/ /g, '_')}`)],
            [Markup.button.callback('📊 CSV Format', `export_format_csv_${subject.replace(/ /g, '_')}`)],
            [Markup.button.callback('❌ Cancel', 'cancel_export_grades')]
        ])
    );
});

// Handle format selection
teacherExportGradesScene.action(/^export_format_(text|csv)_(.+)$/, async (ctx) => {
    const format = ctx.match[1];
    const subject = ctx.match[2].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get all grades for this subject
        const grades = await Grade.find({
            teacherId: teacher.teacherId,
            subject: subject
        }).sort({ studentName: 1, date: -1 });

        if (grades.length === 0) {
            ctx.reply(`❌ No grades found for ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }

        let fileContent;
        let fileName;
        let caption;

        if (format === 'text') {
            // Group grades by student for text report
            const gradesByStudent = {};
            grades.forEach(grade => {
                if (!gradesByStudent[grade.studentId]) {
                    gradesByStudent[grade.studentId] = {
                        studentName: grade.studentName,
                        grades: []
                    };
                }
                gradesByStudent[grade.studentId].grades.push(grade);
            });

            fileContent = generateGradeReport(subject, teacher.name, gradesByStudent);
            fileName = `grades_${subject.replace(/ /g, '_')}_${new Date().toISOString().split('T')[0]}.txt`;
            caption = `📊 Grade report for ${subject} (${grades.length} grades)`;
        } else {
            // CSV format
            fileContent = generateGradeCSV(subject, teacher.name, grades);
            fileName = `grades_${subject.replace(/ /g, '_')}_${new Date().toISOString().split('T')[0]}.csv`;
            caption = `📊 Grade data for ${subject} (${grades.length} records)`;
        }

        // Create temporary file
        const tempDir = './temp_exports';
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        
        const filePath = path.join(tempDir, fileName);
        fs.writeFileSync(filePath, fileContent);

        // Send the file
        await ctx.replyWithDocument({
            source: filePath,
            filename: fileName,
            caption: caption
        });

        // Clean up
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }

        ctx.reply('✅ Grade export completed!', teacherMenu);

    } catch (error) {
        console.error('Error exporting grades:', error);
        ctx.reply('❌ An error occurred while exporting grades.', teacherMenu);
    }
    
    delete ctx.session.exportSubject;
    ctx.scene.leave();
});

// Helper function to generate CSV format
const generateGradeCSV = (subject, teacherName, grades) => {
    let csv = 'Student ID,Student Name,Subject,Score,Purpose,Date,Comments,Teacher\n';
    
    grades.forEach(grade => {
        const row = [
            grade.studentId,
            `"${grade.studentName.replace(/"/g, '""')}"`,
            `"${subject.replace(/"/g, '""')}"`,
            grade.score,
            `"${grade.purpose.replace(/"/g, '""')}"`,
            new Date(grade.date).toISOString().split('T')[0],
            grade.comments ? `"${grade.comments.replace(/"/g, '""')}"` : '',
            `"${teacherName.replace(/"/g, '""')}"`
        ];
        csv += row.join(',') + '\n';
    });

    return csv;
};

// Enhanced grade report generator
const generateGradeReport = (subject, teacherName, gradesByStudent) => {
    let report = `GRADE REPORT - ${subject.toUpperCase()}\n`;
    report += '='.repeat(80) + '\n\n';
    report += `Teacher: ${teacherName}\n`;
    report += `Subject: ${subject}\n`;
    report += `Report Date: ${new Date().toLocaleDateString()}\n`;
    report += `Generated: ${new Date().toLocaleString()}\n`;
    report += '='.repeat(80) + '\n\n';

    let totalStudents = Object.keys(gradesByStudent).length;
    let totalGrades = 0;
    let classTotal = 0;

    // Add student grades
    for (const [studentId, studentData] of Object.entries(gradesByStudent)) {
        report += `STUDENT: ${studentData.studentName}\n`;
        report += `ID: ${studentId}\n`;
        report += '-'.repeat(60) + '\n';
        
        report += 'No. Purpose         Score   Date         Comments\n';
        report += '-'.repeat(60) + '\n';

        let studentTotal = 0;
        let gradeCount = 0;

        studentData.grades.forEach((grade, index) => {
            const purpose = grade.purpose.padEnd(12);
            const score = grade.score.toString().padStart(5);
            const date = new Date(grade.date).toLocaleDateString().padEnd(12);
            const comments = grade.comments ? grade.comments.substring(0, 20) + (grade.comments.length > 20 ? '...' : '') : '';
            
            report += `${(index + 1).toString().padStart(2)}. ${purpose} ${score}%  ${date} ${comments}\n`;

            studentTotal += grade.score;
            gradeCount++;
            totalGrades++;
        });

        // Calculate student average
        if (gradeCount > 0) {
            const average = studentTotal / gradeCount;
            classTotal += average;
            report += '-'.repeat(60) + '\n';
            report += `AVERAGE: ${average.toFixed(2)}%\n`;
            report += `GRADES: ${gradeCount}\n`;
        }

        report += '='.repeat(60) + '\n\n';
    }

    // Add class statistics
    if (totalStudents > 0) {
        const classAverage = classTotal / totalStudents;
        
        report += 'CLASS STATISTICS\n';
        report += '='.repeat(40) + '\n';
        report += `Total Students: ${totalStudents}\n`;
        report += `Total Grades: ${totalGrades}\n`;
        report += `Class Average: ${classAverage.toFixed(2)}%\n`;
        report += `Subject: ${subject}\n`;
        report += `Teacher: ${teacherName}\n`;
        report += `Report Generated: ${new Date().toLocaleString()}\n`;
        report += '='.repeat(40) + '\n';
    }

    return report;
};
// Add this error handling function
const safeFileOperation = async (ctx, filePath, operation) => {
    try {
        return await operation();
    } catch (error) {
        console.error('File operation error:', error);
        ctx.reply('❌ Error creating export file. Please try again.', teacherMenu);
        
        // Clean up if file was created but couldn't be sent
        if (fs.existsSync(filePath)) {
            try {
                fs.unlinkSync(filePath);
            } catch (unlinkError) {
                console.error('Error cleaning up file:', unlinkError);
            }
        }
        
        throw error;
    }
};
// Register the scene
stage.register(teacherExportGradesScene);
// Teacher Search Student Scene
const teacherSearchStudentScene = new Scenes.BaseScene('teacher_search_student_scene');

teacherSearchStudentScene.enter((ctx) => {
    const cancelKeyboard = Markup.keyboard([
        ['❌ Cancel Search']
    ]).resize();

    ctx.reply(
        '🔍 Search students in your database:\n\n' +
        'You can search by:\n' +
        '• Student ID (e.g., ST1234)\n' +
        '• Student Name (full or partial)\n\n' +
        'Enter your search query:',
        cancelKeyboard
    );
});

teacherSearchStudentScene.on('text', async (ctx) => {
    const query = ctx.message.text.trim();
    
    if (query === '❌ Cancel Search') {
        ctx.reply('❌ Search cancelled.', teacherMenu);
        delete ctx.session.searchResults;
        delete ctx.session.currentPage;
        return ctx.scene.leave();
    }

    if (!query) {
        ctx.reply('❌ Please enter a search query.');
        return;
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Search in teacher's database
        const searchResults = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            $or: [
                { studentId: { $regex: query, $options: 'i' } },
                { studentName: { $regex: query, $options: 'i' } }
            ]
        }).sort({ studentName: 1 });

        if (searchResults.length === 0) {
            ctx.reply('❌ No students found matching your search.', teacherMenu);
            return ctx.scene.leave();
        }

        // Store search results and pagination info
        ctx.session.searchResults = searchResults;
        ctx.session.currentPage = 0;
        ctx.session.totalPages = Math.ceil(searchResults.length / 5);

        // Display first page of results
        await displaySearchResults(ctx);

    } catch (error) {
        console.error('Error searching students:', error);
        ctx.reply('❌ An error occurred while searching.', teacherMenu);
        ctx.scene.leave();
    }
});



// Handle pagination actions
teacherSearchStudentScene.action('search_prev_page', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.session.currentPage--;
    await displaySearchResults(ctx);
});

teacherSearchStudentScene.action('search_next_page', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.session.currentPage++;
    await displaySearchResults(ctx);
});

teacherSearchStudentScene.action('search_done', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('✅ Search completed.', teacherMenu);
    delete ctx.session.searchResults;
    delete ctx.session.currentPage;
    delete ctx.session.totalPages;
    ctx.scene.leave();
});

teacherSearchStudentScene.action('search_new', async (ctx) => {
    await ctx.answerCbQuery();
    delete ctx.session.searchResults;
    delete ctx.session.currentPage;
    delete ctx.session.totalPages;
    ctx.scene.reenter();
});

// Handle cancellation from text
teacherSearchStudentScene.hears('❌ Cancel Search', async (ctx) => {
    ctx.reply('❌ Search cancelled.', teacherMenu);
    delete ctx.session.searchResults;
    delete ctx.session.currentPage;
    delete ctx.session.totalPages;
    ctx.scene.leave();
});

// Handle unsupported messages
teacherSearchStudentScene.on('message', (ctx) => {
    if (ctx.message.text !== '❌ Cancel Search') {
        ctx.reply('❌ Please enter a valid search query or use the cancel button.');
    }
});
// Add this to the search scene to handle individual student selection
teacherSearchStudentScene.action(/^view_student_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId
        });

        if (!studentRelation) {
            ctx.reply('❌ Student not found.', teacherMenu);
            return;
        }

        const studentData = await getStudentById(studentId);
        const parent = studentData && studentData.parentId 
            ? await getUserById(studentData.parentId) 
            : null;

        let message = `📋 *Student Details*\n\n`;
        message += `👤 *Name:* ${studentRelation.studentName}\n`;
        message += `🆔 *ID:* ${studentRelation.studentId}\n`;
        message += `📚 *Subject:* ${studentRelation.subject}\n`;
        message += `🏫 *Class:* ${studentRelation.className}\n\n`;

        if (parent) {
            message += `👨‍👩‍👧‍👦 *Parent Information:*\n`;
            message += `   • Name: ${parent.name}\n`;
            message += `   • Telegram ID: ${parent.telegramId}\n`;
            if (parent.username) {
                message += `   • Username: @${parent.username}\n`;
            }
        } else {
            message += `❌ *No parent linked*\n`;
        }

        message += `\n📅 *Added to your class:* ${new Date(studentRelation.addedDate).toLocaleDateString()}`;

        // Create action buttons
        const actionButtons = [
            [Markup.button.callback('💬 Contact Parent', `contact_${studentId}`)],
            [Markup.button.callback('🗑️ Remove from Class', `remove_${studentId}`)],
            [Markup.button.callback('⬅️ Back to Results', 'back_to_results')]
        ];

        ctx.replyWithMarkdown(message, Markup.inlineKeyboard(actionButtons));

    } catch (error) {
        console.error('Error viewing student details:', error);
        ctx.reply('❌ An error occurred.', teacherMenu);
    }
});

// Update the displaySearchResults function to include view buttons
const displaySearchResults = async (ctx) => {
    const { searchResults, currentPage, totalPages } = ctx.session;
    const startIndex = currentPage * 5;
    const endIndex = Math.min(startIndex + 5, searchResults.length);
    const currentResults = searchResults.slice(startIndex, endIndex);

    let message = `🔍 *Search Results (${searchResults.length} found)*\n\n`;
    
    // Display current page results with view buttons
    const viewButtons = [];
    
    for (let i = 0; i < currentResults.length; i++) {
        const student = currentResults[i];
        const studentData = await getStudentById(student.studentId);
        const parentInfo = studentData && studentData.parentId 
            ? `👨‍👩‍👧‍👦 Parent: Linked` 
            : '👨‍👩‍👧‍👦 No parent';
        
        message += `*${startIndex + i + 1}. ${student.studentName}*\n`;
        message += `   🆔 ID: ${student.studentId}\n`;
        message += `   📚 Subject: ${student.subject}\n`;
        message += `   🏫 Class: ${student.className}\n`;
        message += `   ${parentInfo}\n\n`;

        // Add view button for each student
        viewButtons.push([Markup.button.callback(
            `👀 View ${student.studentName}`,
            `view_student_${student.studentId}`
        )]);
    }

    message += `📄 Page ${currentPage + 1} of ${totalPages}\n\n`;

    // Create pagination buttons
    const paginationButtons = [];

    if (currentPage > 0) {
        paginationButtons.push(Markup.button.callback('⬅️ Previous', 'search_prev_page'));
    }

    if (currentPage < totalPages - 1) {
        paginationButtons.push(Markup.button.callback('Next ➡️', 'search_next_page'));
    }

    paginationButtons.push(Markup.button.callback('✅ Done', 'search_done'));
    paginationButtons.push(Markup.button.callback('🔄 New Search', 'search_new'));

    // Combine all buttons
    const allButtons = [...viewButtons, paginationButtons];

    ctx.replyWithMarkdown(message, Markup.inlineKeyboard(allButtons));
};

// Add action handlers for student actions
teacherSearchStudentScene.action(/^contact_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId
        });

        const studentData = await getStudentById(studentId);
        
        if (!studentData || !studentData.parentId) {
            ctx.reply('❌ Student has no linked parent.', teacherMenu);
            return;
        }

        // Store contact info and switch to message mode
        ctx.session.contactInfo = {
            studentId: studentId,
            studentName: studentRelation.studentName,
            parentId: studentData.parentId,
            subject: studentRelation.subject
        };

        const parent = await getUserById(studentData.parentId);
        const parentName = parent ? parent.name : 'Parent';

        const cancelKeyboard = Markup.keyboard([
            ['❌ Cancel Message']
        ]).resize();

        ctx.reply(
            `📞 Ready to contact ${parentName}, parent of ${studentRelation.studentName}:\n\n` +
            `Please type your message:`,
            cancelKeyboard
        );

    } catch (error) {
        console.error('Error preparing contact:', error);
        ctx.reply('❌ An error occurred.', teacherMenu);
    }
});

teacherSearchStudentScene.action(/^remove_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId
        });

        ctx.reply(
            `⚠️ *Confirm Removal*\n\n` +
            `Are you sure you want to remove ${studentRelation.studentName} (${studentId}) ` +
            `from your ${studentRelation.subject} class?`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Yes, Remove', `confirm_remove_${studentId}`)],
                [Markup.button.callback('❌ No, Cancel', 'back_to_results')]
            ])
        );

    } catch (error) {
        console.error('Error preparing removal:', error);
        ctx.reply('❌ An error occurred.', teacherMenu);
    }
});

teacherSearchStudentScene.action(/^confirm_remove_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId
        });

        await TeacherStudent.deleteOne({
            teacherId: teacher.teacherId,
            studentId: studentId,
            subject: studentRelation.subject
        });

        ctx.reply(
            `✅ Successfully removed ${studentRelation.studentName} from your ${studentRelation.subject} class.`,
            teacherMenu
        );

        // Clean up and return to menu
        delete ctx.session.searchResults;
        delete ctx.session.currentPage;
        delete ctx.session.totalPages;
        ctx.scene.leave();

    } catch (error) {
        console.error('Error removing student:', error);
        ctx.reply('❌ An error occurred while removing the student.', teacherMenu);
    }
});

teacherSearchStudentScene.action('back_to_results', async (ctx) => {
    await ctx.answerCbQuery();
    await displaySearchResults(ctx);
});

// Handle message sending from search results
teacherSearchStudentScene.on('text', async (ctx) => {
    const message = ctx.message.text.trim();
    
    if (message === '❌ Cancel Message') {
        ctx.reply('❌ Message cancelled.', teacherMenu);
        delete ctx.session.contactInfo;
        return;
    }

    const contactInfo = ctx.session.contactInfo;
    if (!contactInfo) {
        return; // Not in message sending mode
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const parent = await getUserById(contactInfo.parentId);
        
        // Send message to parent
        await ctx.telegram.sendMessage(
            contactInfo.parentId,
            `📞 *Message from ${teacher.name} (${contactInfo.subject} Teacher):*\n${message}`,
            { parse_mode: 'Markdown' }
        );

        ctx.reply(
            `✅ Message sent to ${parent.name}, parent of ${contactInfo.studentName}.`,
            teacherMenu
        );

    } catch (error) {
        if (error.response?.error_code === 403) {
            ctx.reply('❌ Failed to send message. The parent may have blocked the bot.', teacherMenu);
        } else {
            console.error('Error sending message:', error);
            ctx.reply('❌ An error occurred while sending the message.', teacherMenu);
        }
    }
    
    delete ctx.session.contactInfo;
    ctx.scene.leave();
});
// Register the scene
stage.register(teacherSearchStudentScene);
// Teacher Contact Parent Scene
const teacherContactParentScene = new Scenes.BaseScene('teacher_contact_parent_scene');

teacherContactParentScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher) {
            ctx.reply('❌ Teacher profile not found.', teacherMenu);
            return ctx.scene.leave();
        }

        // Check if teacher has any students
        const studentCount = await TeacherStudent.countDocuments({ teacherId: teacher.teacherId });
        
        if (studentCount === 0) {
            ctx.reply('❌ You have no students in your database.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create contact option buttons
        ctx.reply(
            '📞 How would you like to contact a parent?',
            Markup.inlineKeyboard([
                [Markup.button.callback('🆔 Contact by Student ID', 'contact_by_id')],
                [Markup.button.callback('📋 Contact from Student List', 'contact_by_list')],
                [Markup.button.callback('❌ Cancel', 'cancel_contact_parent')]
            ])
        );

    } catch (error) {
        console.error('Error in teacher contact parent scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});
// Action handlers for teacher contact parent scene
teacherContactParentScene.action('contact_by_id', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('contact_parent_by_id_scene');
});

teacherContactParentScene.action('contact_by_list', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('contact_parent_by_list_scene');
});

teacherContactParentScene.action('cancel_contact_parent', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Contact parent cancelled.', teacherMenu);
    ctx.scene.leave();
});
// Contact by ID Scene
const contactParentByIdScene = new Scenes.BaseScene('contact_parent_by_id_scene');

contactParentByIdScene.enter((ctx) => {
    const cancelKeyboard = Markup.keyboard([
        ['❌ Cancel Operation']
    ]).resize();

    ctx.reply('🆔 Please enter the Student ID to contact their parent:', cancelKeyboard);
});

contactParentByIdScene.on('text', async (ctx) => {
    const studentId = ctx.message.text.trim();
    
    if (studentId === '❌ Cancel Operation') {
        ctx.reply('❌ Contact parent cancelled.', teacherMenu);
        return ctx.scene.leave();
    }

    if (!isValidStudentId(studentId)) {
        ctx.reply('❌ Invalid Student ID. Please provide a valid student ID (e.g., ST1234).');
        return;
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Check if student exists in teacher's database
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId
        });

        if (!studentRelation) {
            ctx.reply('❌ Student not found in your database. Please check the Student ID.', teacherMenu);
            return ctx.scene.leave();
        }

        // Get student details from main database
        const student = await getStudentById(studentId);
        if (!student || !student.parentId) {
            ctx.reply('❌ Student has no linked parent or parent not found.', teacherMenu);
            return ctx.scene.leave();
        }

        // Get parent details
        const parent = await getUserById(student.parentId);
        if (!parent) {
            ctx.reply('❌ Parent not found for this student.', teacherMenu);
            return ctx.scene.leave();
        }

        // Store contact info in session
        ctx.session.contactInfo = {
            studentId: studentId,
            studentName: studentRelation.studentName,
            parentId: student.parentId,
            parentName: parent.name,
            subject: studentRelation.subject
        };

        const cancelKeyboard = Markup.keyboard([
            ['❌ Cancel Message']
        ]).resize();

        ctx.reply(
            `📞 Ready to contact parent of ${studentRelation.studentName}:\n\n` +
            `👤 Student: ${studentRelation.studentName} (${studentId})\n` +
            `📚 Subject: ${studentRelation.subject}\n` +
            `👨‍👩‍👧‍👦 Parent: ${parent.name}\n\n` +
            `Please type your message to send to the parent:`,
            cancelKeyboard
        );

    } catch (error) {
        console.error('Error processing student ID:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

contactParentByIdScene.on('text', async (ctx) => {
    const message = ctx.message.text.trim();
    
    if (message === '❌ Cancel Message') {
        ctx.reply('❌ Message cancelled.', teacherMenu);
        delete ctx.session.contactInfo;
        return ctx.scene.leave();
    }

    const contactInfo = ctx.session.contactInfo;
    if (!contactInfo) {
        ctx.reply('❌ Contact information not found. Please start over.', teacherMenu);
        return ctx.scene.leave();
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Send message to parent
        await ctx.telegram.sendMessage(
            contactInfo.parentId,
            `📞 *Message from ${teacher.name} (${contactInfo.subject} Teacher):*\n${message}`,
            { parse_mode: 'Markdown' }
        );

        ctx.reply(
            `✅ Message sent to ${contactInfo.parentName}, parent of ${contactInfo.studentName}.`,
            teacherMenu
        );

    } catch (error) {
        if (error.response?.error_code === 403) {
            ctx.reply('❌ Failed to send message. The parent may have blocked the bot.', teacherMenu);
        } else {
            console.error('Error sending message:', error);
            ctx.reply('❌ An error occurred while sending the message.', teacherMenu);
        }
    }
    
    delete ctx.session.contactInfo;
    ctx.scene.leave();
});

contactParentByIdScene.hears('❌ Cancel Operation', async (ctx) => {
    ctx.reply('❌ Contact parent cancelled.', teacherMenu);
    delete ctx.session.contactInfo;
    ctx.scene.leave();
});
// Contact by List Scene
const contactParentByListScene = new Scenes.BaseScene('contact_parent_by_list_scene');

contactParentByListScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get subjects that have students
        const subjectsWithStudents = await TeacherStudent.aggregate([
            { $match: { teacherId: teacher.teacherId } },
            { $group: { _id: '$subject', count: { $sum: 1 } } },
            { $match: { count: { $gt: 0 } } }
        ]);

        if (subjectsWithStudents.length === 0) {
            ctx.reply('❌ You have no students in any subjects.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = subjectsWithStudents.map(subject => 
            [Markup.button.callback(`${subject._id} (${subject.count} students)`, `contact_from_subject_${subject._id.replace(/ /g, '_')}`)]
        );
        
        subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_contact_list')]);

        ctx.reply('📚 Select a subject to contact parents from:', Markup.inlineKeyboard(subjectButtons));

    } catch (error) {
        console.error('Error in contact by list scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject selection
contactParentByListScene.action(/^contact_from_subject_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get students for this subject with parent information
        const students = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            subject: subject
        }).sort({ studentName: 1 });

        if (students.length === 0) {
            ctx.reply(`❌ No students found in ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Get parent information for each student
        const studentsWithParents = await Promise.all(
            students.map(async (student) => {
                const studentData = await getStudentById(student.studentId);
                const hasParent = studentData && studentData.parentId;
                return {
                    ...student.toObject(),
                    hasParent: hasParent,
                    parentId: hasParent ? studentData.parentId : null
                };
            })
        );

        // Filter out students without parents
        const studentsWithValidParents = studentsWithParents.filter(s => s.hasParent);

        if (studentsWithValidParents.length === 0) {
            ctx.reply(`❌ No students in ${subject} have linked parents.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Create student buttons
        const studentButtons = studentsWithValidParents.map(student => 
            [Markup.button.callback(
                `${student.studentName} (${student.studentId})`, 
                `contact_parent_${student.studentId}_${subject.replace(/ /g, '_')}`
            )]
        );
        
        // Add back and cancel buttons
        studentButtons.push(
            [Markup.button.callback('⬅️ Back to Subjects', 'back_to_subjects_contact')],
            [Markup.button.callback('❌ Cancel', 'cancel_contact_list')]
        );

        ctx.reply(
            `👥 Students in ${subject} with parents:\n\n` +
            `Select a student to contact their parent:`,
            Markup.inlineKeyboard(studentButtons)
        );

    } catch (error) {
        console.error('Error selecting subject:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle student selection for contact
contactParentByListScene.action(/^contact_parent_(.+)_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    const subject = ctx.match[2].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get student and parent details
        const student = await getStudentById(studentId);
        const parent = await getUserById(student.parentId);
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId,
            subject: subject
        });

        if (!student || !parent || !studentRelation) {
            ctx.reply('❌ Student or parent information not found.', teacherMenu);
            return ctx.scene.leave();
        }

        // Store contact info in session
        ctx.session.contactInfo = {
            studentId: studentId,
            studentName: studentRelation.studentName,
            parentId: student.parentId,
            parentName: parent.name,
            subject: subject
        };

        const cancelKeyboard = Markup.keyboard([
            ['❌ Cancel Message']
        ]).resize();

        ctx.reply(
            `📞 Ready to contact parent of ${studentRelation.studentName}:\n\n` +
            `👤 Student: ${studentRelation.studentName} (${studentId})\n` +
            `📚 Subject: ${subject}\n` +
            `👨‍👩‍👧‍👦 Parent: ${parent.name}\n\n` +
            `Please type your message to send to the parent:`,
            cancelKeyboard
        );

    } catch (error) {
        console.error('Error selecting student:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle message sending for list contact
contactParentByListScene.on('text', async (ctx) => {
    const message = ctx.message.text.trim();
    
    if (message === '❌ Cancel Message') {
        ctx.reply('❌ Message cancelled.', teacherMenu);
        delete ctx.session.contactInfo;
        return ctx.scene.leave();
    }

    const contactInfo = ctx.session.contactInfo;
    if (!contactInfo) {
        return; // Not in message sending mode
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Send message to parent
        await ctx.telegram.sendMessage(
            contactInfo.parentId,
            `📞 *Message from ${teacher.name} (${contactInfo.subject} Teacher):*\n${message}`,
            { parse_mode: 'Markdown' }
        );

        ctx.reply(
            `✅ Message sent to ${contactInfo.parentName}, parent of ${contactInfo.studentName}.`,
            teacherMenu
        );

    } catch (error) {
        if (error.response?.error_code === 403) {
            ctx.reply('❌ Failed to send message. The parent may have blocked the bot.', teacherMenu);
        } else {
            console.error('Error sending message:', error);
            ctx.reply('❌ An error occurred while sending the message.', teacherMenu);
        }
    }
    
    delete ctx.session.contactInfo;
    ctx.scene.leave();
});

// Handle back to subjects
contactParentByListScene.action('back_to_subjects_contact', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.reenter(); // Go back to subject selection
});

// Handle cancellation
contactParentByListScene.action('cancel_contact_list', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Contact parent cancelled.', teacherMenu);
    delete ctx.session.contactInfo;
    ctx.scene.leave();
});
// Register the scenes
stage.register(teacherContactParentScene);
stage.register(contactParentByIdScene);
stage.register(contactParentByListScene);
// Teacher Remove Student Scene
const teacherRemoveStudentScene = new Scenes.BaseScene('teacher_remove_student_scene');

teacherRemoveStudentScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher) {
            ctx.reply('❌ Teacher profile not found.', teacherMenu);
            return ctx.scene.leave();
        }

        // Check if teacher has any students
        const studentCount = await TeacherStudent.countDocuments({ teacherId: teacher.teacherId });
        
        if (studentCount === 0) {
            ctx.reply('❌ You have no students in your database.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create removal option buttons
        ctx.reply(
            '🗑️ How would you like to remove students?',
            Markup.inlineKeyboard([
                [Markup.button.callback('🆔 Remove by Student ID', 'remove_by_id')],
                [Markup.button.callback('📋 Remove from Subject List', 'remove_by_list')],
                [Markup.button.callback('❌ Cancel', 'cancel_remove_student')]
            ])
        );

    } catch (error) {
        console.error('Error in teacher remove student scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});
// Action handlers for teacher remove student scene
teacherRemoveStudentScene.action('remove_by_id', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('remove_student_by_id_scene');
});

teacherRemoveStudentScene.action('remove_by_list', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('remove_student_by_list_scene');
});

teacherRemoveStudentScene.action('cancel_remove_student', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Student removal cancelled.', teacherMenu);
    ctx.scene.leave();
});
// Remove by ID Scene
const removeStudentByIdScene = new Scenes.BaseScene('remove_student_by_id_scene');

removeStudentByIdScene.enter((ctx) => {
    const cancelKeyboard = Markup.keyboard([
        ['❌ Cancel Operation']
    ]).resize();

    ctx.reply('🆔 Please enter the Student ID to remove from your database:', cancelKeyboard);
});

removeStudentByIdScene.on('text', async (ctx) => {
    const studentId = ctx.message.text.trim();
    
    if (studentId === '❌ Cancel Operation') {
        ctx.reply('❌ Student removal cancelled.', teacherMenu);
        return ctx.scene.leave();
    }

    if (!isValidStudentId(studentId)) {
        ctx.reply('❌ Invalid Student ID. Please provide a valid student ID (e.g., ST1234).');
        return;
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Check if student exists in teacher's database
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId
        });

        if (!studentRelation) {
            ctx.reply('❌ Student not found in your database. Please check the Student ID.', teacherMenu);
            return ctx.scene.leave();
        }

        // Store student info for confirmation
        ctx.session.studentToRemove = {
            studentId: studentId,
            studentName: studentRelation.studentName,
            subject: studentRelation.subject
        };

        // Ask for confirmation
        ctx.reply(
            `⚠️ *Confirm Removal*\n\n` +
            `Are you sure you want to remove ${studentRelation.studentName} (${studentId}) ` +
            `from your ${studentRelation.subject} class?\n\n` +
            `*This will only remove them from your database, not from the school system.*`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Yes, Remove', 'confirm_remove_by_id')],
                [Markup.button.callback('❌ No, Cancel', 'cancel_remove_operation')]
            ])
        );

    } catch (error) {
        console.error('Error processing student ID:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

removeStudentByIdScene.action('confirm_remove_by_id', async (ctx) => {
    await ctx.answerCbQuery();

    try {
        const { studentId, studentName, subject } = ctx.session.studentToRemove;
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });

        // Remove the student from teacher's database
        await TeacherStudent.deleteOne({
            teacherId: teacher.teacherId,
            studentId: studentId,
            subject: subject
        });

        ctx.reply(
            `✅ Successfully removed ${studentName} (${studentId}) from your ${subject} class.`,
            teacherMenu
        );

    } catch (error) {
        console.error('Error removing student:', error);
        ctx.reply('❌ An error occurred while removing the student.', teacherMenu);
    }
    
    delete ctx.session.studentToRemove;
    ctx.scene.leave();
});

removeStudentByIdScene.action('cancel_remove_operation', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Student removal cancelled.', teacherMenu);
    delete ctx.session.studentToRemove;
    ctx.scene.leave();
});

removeStudentByIdScene.hears('❌ Cancel Operation', async (ctx) => {
    ctx.reply('❌ Student removal cancelled.', teacherMenu);
    delete ctx.session.studentToRemove;
    ctx.scene.leave();
});
// Remove by List Scene
const removeStudentByListScene = new Scenes.BaseScene('remove_student_by_list_scene');

removeStudentByListScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get subjects that have students
        const subjectsWithStudents = await TeacherStudent.aggregate([
            { $match: { teacherId: teacher.teacherId } },
            { $group: { _id: '$subject', count: { $sum: 1 } } },
            { $match: { count: { $gt: 0 } } }
        ]);

        if (subjectsWithStudents.length === 0) {
            ctx.reply('❌ You have no students in any subjects.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = subjectsWithStudents.map(subject => 
            [Markup.button.callback(`${subject._id} (${subject.count} students)`, `remove_from_subject_${subject._id.replace(/ /g, '_')}`)]
        );
        
        subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_remove_list')]);

        ctx.reply('📚 Select a subject to remove students from:', Markup.inlineKeyboard(subjectButtons));

    } catch (error) {
        console.error('Error in remove by list scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject selection
removeStudentByListScene.action(/^remove_from_subject_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get students for this subject
        const students = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            subject: subject
        }).sort({ studentName: 1 });

        if (students.length === 0) {
            ctx.reply(`❌ No students found in ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Create student buttons (grouped to avoid too many buttons)
        const studentButtons = students.map(student => 
            [Markup.button.callback(
                `${student.studentName} (${student.studentId})`, 
                `remove_student_${student.studentId}_${subject.replace(/ /g, '_')}`
            )]
        );
        
        // Add back and cancel buttons
        studentButtons.push(
            [Markup.button.callback('⬅️ Back to Subjects', 'back_to_subjects_list')],
            [Markup.button.callback('❌ Cancel', 'cancel_remove_list')]
        );

        ctx.reply(
            `👥 Students in ${subject}:\n\n` +
            `Select a student to remove:`,
            Markup.inlineKeyboard(studentButtons)
        );

    } catch (error) {
        console.error('Error selecting subject:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle student selection for removal
removeStudentByListScene.action(/^remove_student_(.+)_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    const subject = ctx.match[2].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const studentRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId,
            subject: subject
        });

        if (!studentRelation) {
            ctx.reply('❌ Student not found.', teacherMenu);
            return ctx.scene.leave();
        }

        // Ask for confirmation
        ctx.reply(
            `⚠️ *Confirm Removal*\n\n` +
            `Are you sure you want to remove ${studentRelation.studentName} (${studentId}) ` +
            `from your ${subject} class?\n\n` +
            `*This will only remove them from your database, not from the school system.*`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Yes, Remove', `confirm_list_remove_${studentId}_${subject.replace(/ /g, '_')}`)],
                [Markup.button.callback('❌ No, Cancel', 'cancel_remove_list')]
            ])
        );

    } catch (error) {
        console.error('Error selecting student:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle confirmation for list removal
removeStudentByListScene.action(/^confirm_list_remove_(.+)_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    const subject = ctx.match[2].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Remove the student
        const result = await TeacherStudent.deleteOne({
            teacherId: teacher.teacherId,
            studentId: studentId,
            subject: subject
        });

        if (result.deletedCount > 0) {
            ctx.reply(
                `✅ Successfully removed student from your ${subject} class.`,
                teacherMenu
            );
        } else {
            ctx.reply('❌ Student not found or already removed.', teacherMenu);
        }

    } catch (error) {
        console.error('Error removing student:', error);
        ctx.reply('❌ An error occurred while removing the student.', teacherMenu);
    }
    
    ctx.scene.leave();
});

// Handle back to subjects
removeStudentByListScene.action('back_to_subjects_list', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.reenter(); // Go back to subject selection
});

// Handle cancellation
removeStudentByListScene.action('cancel_remove_list', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Student removal cancelled.', teacherMenu);
    ctx.scene.leave();
});
// Register the scenes
stage.register(teacherRemoveStudentScene);
stage.register(removeStudentByIdScene);
stage.register(removeStudentByListScene);
// Announce Class Scene
const announceClassScene = new Scenes.BaseScene('announce_class_scene');

announceClassScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no subjects assigned.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(subject, `announce_subject_${subject.replace(/ /g, '_')}`)]
        );
        
        // Add cancel button
        subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_announcement')]);

        ctx.reply('📚 Select the subject to announce to:', Markup.inlineKeyboard(subjectButtons));

    } catch (error) {
        console.error('Error in announce class scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject selection
announceClassScene.action(/^announce_subject_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Get students for this subject
        const studentRelations = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            subject: subject
        });

        if (studentRelations.length === 0) {
            ctx.reply(`❌ No students found for ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Get unique parent IDs
        const studentIds = studentRelations.map(rel => rel.studentId);
        const students = await Student.find({ studentId: { $in: studentIds } });
        const parentIds = [...new Set(students.map(s => s.parentId).filter(id => id !== null))];

        if (parentIds.length === 0) {
            ctx.reply(`❌ No parents found for students in ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Store announcement data in session
        ctx.session.announcementData = {
            subject: subject,
            parentIds: parentIds,
            studentCount: studentRelations.length,
            parentCount: parentIds.length
        };

        const cancelKeyboard = Markup.keyboard([
            ['❌ Cancel Announcement']
        ]).resize();

        ctx.reply(
            `📢 Ready to announce to ${subject} class!\n\n` +
            `• Students: ${studentRelations.length}\n` +
            `• Parents: ${parentIds.length}\n\n` +
            `Please send your announcement (text, photo, video, document, audio, or voice):`,
            cancelKeyboard
        );

    } catch (error) {
        console.error('Error selecting subject for announcement:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle all message types for announcement
announceClassScene.on(['text', 'photo', 'video', 'document', 'audio', 'voice'], async (ctx) => {
    const announcementData = ctx.session.announcementData;
    
    if (!announcementData) {
        ctx.reply('❌ No subject selected. Please start over.', teacherMenu);
        return ctx.scene.leave();
    }

    const { subject, parentIds, studentCount, parentCount } = announcementData;
    const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
    const teacherName = teacher?.name || 'Teacher';

    let successCount = 0;
    let failedCount = 0;
    const failedParents = [];

    try {
        // Send announcement to each parent
        for (const parentId of parentIds) {
            try {
                if (ctx.message.text) {
                    // Text message
                    await ctx.telegram.sendMessage(
                        parentId,
                        `📢 *Announcement from ${teacherName} (${subject}):*\n${ctx.message.text}`,
                        { parse_mode: 'Markdown' }
                    );
                    successCount++;
                } 
                else if (ctx.message.photo) {
                    // Photo with optional caption
                    const photo = ctx.message.photo[ctx.message.photo.length - 1];
                    const caption = ctx.message.caption 
                        ? `📢 *Announcement from ${teacherName} (${subject}):*\n${ctx.message.caption}`
                        : `📢 Announcement from ${teacherName} (${subject})`;
                    
                    await ctx.telegram.sendPhoto(
                        parentId,
                        photo.file_id,
                        { caption, parse_mode: 'Markdown' }
                    );
                    successCount++;
                }
                else if (ctx.message.video) {
                    // Video with optional caption
                    const caption = ctx.message.caption 
                        ? `📢 *Announcement from ${teacherName} (${subject}):*\n${ctx.message.caption}`
                        : `📢 Announcement from ${teacherName} (${subject})`;
                    
                    await ctx.telegram.sendVideo(
                        parentId,
                        ctx.message.video.file_id,
                        { caption, parse_mode: 'Markdown' }
                    );
                    successCount++;
                }
                else if (ctx.message.document) {
                    // Document with optional caption
                    const caption = ctx.message.caption 
                        ? `📢 *Announcement from ${teacherName} (${subject}):*\n${ctx.message.caption}`
                        : `📢 Announcement from ${teacherName} (${subject})`;
                    
                    await ctx.telegram.sendDocument(
                        parentId,
                        ctx.message.document.file_id,
                        { caption, parse_mode: 'Markdown' }
                    );
                    successCount++;
                }
                else if (ctx.message.audio) {
                    // Audio with optional caption
                    const caption = ctx.message.caption 
                        ? `📢 *Announcement from ${teacherName} (${subject}):*\n${ctx.message.caption}`
                        : `📢 Announcement from ${teacherName} (${subject})`;
                    
                    await ctx.telegram.sendAudio(
                        parentId,
                        ctx.message.audio.file_id,
                        { caption, parse_mode: 'Markdown' }
                    );
                    successCount++;
                }
                else if (ctx.message.voice) {
                    // Voice message with announcement header
                    await ctx.telegram.sendVoice(
                        parentId,
                        ctx.message.voice.file_id
                    );
                    await ctx.telegram.sendMessage(
                        parentId,
                        `🗣️ *Voice announcement from ${teacherName} (${subject})*`,
                        { parse_mode: 'Markdown' }
                    );
                    successCount++;
                }
            } catch (error) {
                if (error.response?.error_code === 403) {
                    // Parent blocked the bot
                    failedCount++;
                    failedParents.push(parentId);
                } else {
                    console.error(`Failed to send to parent ${parentId}:`, error);
                    failedCount++;
                    failedParents.push(parentId);
                }
            }
        }

        // Send summary to teacher
        let summaryMessage = `✅ Announcement sent!\n\n`;
        summaryMessage += `📚 Subject: ${subject}\n`;
        summaryMessage += `👥 Students: ${studentCount}\n`;
        summaryMessage += `👨‍👩‍👧‍👦 Parents: ${parentCount}\n`;
        summaryMessage += `✅ Successful: ${successCount}\n`;
        
        if (failedCount > 0) {
            summaryMessage += `❌ Failed: ${failedCount}\n`;
            if (failedParents.length > 0) {
                summaryMessage += `\nFailed to send to ${failedCount} parent(s).`;
            }
        }

        ctx.reply(summaryMessage, teacherMenu);

    } catch (error) {
        console.error('Error sending announcement:', error);
        ctx.reply('❌ An error occurred while sending the announcement.', teacherMenu);
    }

    // Clean up session
    delete ctx.session.announcementData;
    ctx.scene.leave();
});

// Handle cancellation
announceClassScene.action('cancel_announcement', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Announcement cancelled.', teacherMenu);
    delete ctx.session.announcementData;
    ctx.scene.leave();
});

// Handle text cancellation
announceClassScene.hears('❌ Cancel Announcement', async (ctx) => {
    ctx.reply('❌ Announcement cancelled.', teacherMenu);
    delete ctx.session.announcementData;
    ctx.scene.leave();
});

// Handle unsupported media types
announceClassScene.on('message', (ctx) => {
    ctx.reply('❌ Unsupported message type. Please send text, photo, video, document, audio, or voice.');
});
// Register the scene
stage.register(announceClassScene);
/// Teacher My Subjects Scene
const teacherMySubjectsScene = new Scenes.BaseScene('teacher_my_subjects_scene');

teacherMySubjectsScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher) {
            ctx.reply('❌ Teacher profile not found.', teacherMenu);
            return ctx.scene.leave();
        }

        const currentSubjects = teacher.subjects || [];
        const pendingSubjects = teacher.pendingSubjects || [];

        let message = '📖 *Your Subjects:*\n\n';
        
        if (currentSubjects.length > 0) {
            message += '✅ *Approved Subjects:*\n';
            currentSubjects.forEach((subject, index) => {
                message += `${index + 1}. ${subject}\n`;
            });
            message += '\n';
        }

        if (pendingSubjects.length > 0) {
            message += '⏳ *Pending Approval:*\n';
            pendingSubjects.forEach((subject, index) => {
                message += `${index + 1}. ${subject}\n`;
            });
            message += '\n';
        }

        if (currentSubjects.length === 0 && pendingSubjects.length === 0) {
            message += '❌ You have no subjects assigned yet.\n';
        }

        // Create action buttons with cancel option
        const actionButtons = [
            [Markup.button.callback('➕ Add New Subject', 'add_new_subject')],
            [Markup.button.callback('➖ Remove Subject', 'remove_subject')],
            [Markup.button.callback('⬅️ Back to Menu', 'back_to_teacher_menu')]
        ];

        ctx.replyWithMarkdown(message, Markup.inlineKeyboard(actionButtons));

    } catch (error) {
        console.error('Error in teacher my subjects scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Add text handler for "Back to Menu" or "Cancel"
teacherMySubjectsScene.hears(['⬅️ Back to Menu', '❌ Cancel', '🔙 Back'], async (ctx) => {
    ctx.reply('⬅️ Returning to teacher menu.', teacherMenu);
    ctx.scene.leave();
});
// Action handlers for teacher my subjects scene
teacherMySubjectsScene.action('add_new_subject', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('add_subject_scene');
});

teacherMySubjectsScene.action('remove_subject', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('remove_subject_scene');
});

teacherMySubjectsScene.action('back_to_teacher_menu', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('⬅️ Returning to teacher menu.', teacherMenu);
    ctx.scene.leave();
});

/// Add Subject Scene
const addTeacherSubjectScene = new Scenes.BaseScene('add_subject_scene');

addTeacherSubjectScene.enter((ctx) => {
    const cancelKeyboard = Markup.keyboard([
        ['❌ Cancel', '⬅️ Back to Menu']
    ]).resize();

    ctx.reply('📝 Please enter the new subject you want to add (admin approval required):', cancelKeyboard);
});

addTeacherSubjectScene.on('text', async (ctx) => {
    const newSubject = ctx.message.text.trim();
    
    if (newSubject === '❌ Cancel' || newSubject === '⬅️ Back to Menu') {
        ctx.reply('❌ Subject addition cancelled.', teacherMenu);
        return ctx.scene.leave();
    }

    if (!isValidSubject(newSubject)) {
        ctx.reply('❌ Invalid subject. Please enter a non-empty subject name (max 50 characters).');
        return;
    }

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher) {
            ctx.reply('❌ Teacher profile not found.', teacherMenu);
            return ctx.scene.leave();
        }

        // Check if subject already exists or is pending
        const currentSubjects = teacher.subjects || [];
        const pendingSubjects = teacher.pendingSubjects || [];

        if (currentSubjects.includes(newSubject)) {
            ctx.reply(`❌ "${newSubject}" is already one of your approved subjects.`, teacherMenu);
            return ctx.scene.leave();
        }

        if (pendingSubjects.includes(newSubject)) {
            ctx.reply(`❌ "${newSubject}" is already pending approval.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Add to pending subjects
        teacher.pendingSubjects = [...pendingSubjects, newSubject];
        await teacher.save();

        // Notify admins
        const admins = await getAdmins();
        for (const admin of admins) {
            try {
                await ctx.telegram.sendMessage(
                    admin.telegramId,
                    `🔔 *New Subject Request from ${teacher.name}:*\n` +
                    `Subject: **${newSubject}**\n` +
                    `Teacher ID: **${teacher.teacherId}**\n` +
                    `Telegram ID: ${ctx.from.id}`,
                    {
                        parse_mode: 'Markdown',
                        ...Markup.inlineKeyboard([
                            [Markup.button.callback('✅ Approve', `approve_subject_${teacher.teacherId}_${newSubject.replace(/ /g, '_')}`)],
                            [Markup.button.callback('❌ Deny', `deny_subject_${teacher.teacherId}_${newSubject.replace(/ /g, '_')}`)]
                        ])
                    }
                );
            } catch (error) {
                console.error(`Failed to notify admin ${admin.telegramId}:`, error);
            }
        }

        ctx.reply(`✅ Your request to add "${newSubject}" has been sent for admin approval.`, teacherMenu);

    } catch (error) {
        console.error('Error adding subject:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
    }
    
    ctx.scene.leave();
});

addTeacherSubjectScene.hears(['❌ Cancel', '⬅️ Back to Menu'], async (ctx) => {
    ctx.reply('❌ Subject addition cancelled.', teacherMenu);
    ctx.scene.leave();
});
// Remove Subject Scene
const removeTeacherSubjectScene = new Scenes.BaseScene('remove_subject_scene');

removeTeacherSubjectScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no subjects to remove.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject buttons for removal with back option
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(`🗑️ ${subject}`, `remove_subject_${subject.replace(/ /g, '_')}`)]
        );
        
        subjectButtons.push([Markup.button.callback('⬅️ Back to Menu', 'back_to_teacher_menu')]);

        ctx.reply('📚 Select a subject to remove:', Markup.inlineKeyboard(subjectButtons));

    } catch (error) {
        console.error('Error in remove subject scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject removal selection
removeTeacherSubjectScene.action(/^remove_subject_(.+)$/, async (ctx) => {
    const subjectToRemove = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher || !teacher.subjects.includes(subjectToRemove)) {
            ctx.reply('❌ Subject not found.', teacherMenu);
            return ctx.scene.leave();
        }

        // Ask for confirmation with back option
        ctx.reply(
            `⚠️ *Confirm Removal*\n\n` +
            `Are you sure you want to remove "${subjectToRemove}" from your subjects?\n\n` +
            `*This will also remove all student relationships for this subject!*`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Yes, Remove', `confirm_remove_${subjectToRemove.replace(/ /g, '_')}`)],
                [Markup.button.callback('⬅️ Back to Menu', 'back_to_teacher_menu')]
            ])
        );

    } catch (error) {
        console.error('Error selecting subject for removal:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle removal confirmation
removeTeacherSubjectScene.action(/^confirm_remove_(.+)$/, async (ctx) => {
    const subjectToRemove = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        if (!teacher) {
            ctx.reply('❌ Teacher profile not found.', teacherMenu);
            return ctx.scene.leave();
        }

        // Remove subject from teacher
        teacher.subjects = teacher.subjects.filter(s => s !== subjectToRemove);
        await teacher.save();

        // Remove subject from user record
        const user = await getUserById(ctx.from.id);
        if (user) {
            user.subjects = user.subjects.filter(s => s !== subjectToRemove);
            await user.save();
        }

        // Remove all teacher-student relationships for this subject
        await TeacherStudent.deleteMany({
            teacherId: teacher.teacherId,
            subject: subjectToRemove
        });

        ctx.reply(`✅ Subject "${subjectToRemove}" has been removed successfully.`, teacherMenu);

    } catch (error) {
        console.error('Error removing subject:', error);
        ctx.reply('❌ An error occurred while removing the subject.', teacherMenu);
    }
    
    ctx.scene.leave();
});

// Handle back to menu action
removeTeacherSubjectScene.action('back_to_teacher_menu', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('⬅️ Returning to teacher menu.', teacherMenu);
    ctx.scene.leave();
});

// Add text handler for back to menu
removeTeacherSubjectScene.hears(['⬅️ Back to Menu', '❌ Cancel', '🔙 Back'], async (ctx) => {
    ctx.reply('⬅️ Returning to teacher menu.', teacherMenu);
    ctx.scene.leave();
});
// Register the scenes
stage.register(teacherMySubjectsScene);
stage.register(addTeacherSubjectScene);
stage.register(removeTeacherSubjectScene);

// Teacher Add Student Scene
const teacherAddStudentScene = new Scenes.BaseScene('teacher_add_student_scene');

teacherAddStudentScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no subjects assigned. Please add subjects first.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create a keyboard with cancel option
        const cancelKeyboard = Markup.keyboard([
            ['❌ Cancel']
        ]).resize();

        ctx.reply('🆔 Please enter the Student ID you want to add to your class:', cancelKeyboard);
    } catch (error) {
        console.error('Error in teacher add student scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

teacherAddStudentScene.on('text', async (ctx) => {
    const studentId = ctx.message.text.trim();
    
    if (studentId === '❌ Cancel') {
        ctx.reply('❌ Student addition cancelled.', teacherMenu);
        return ctx.scene.leave();
    }

    if (!isValidStudentId(studentId)) {
        ctx.reply('❌ Invalid Student ID. Please provide a valid student ID (e.g., ST1234).');
        return;
    }

    try {
        const student = await getStudentById(studentId);
        if (!student) {
            ctx.reply('❌ Student not found. Please check the Student ID and try again.');
            return;
        }

        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        
        // Store student info in session
        ctx.session.studentToAdd = {
            studentId: student.studentId,
            studentName: student.name,
            className: student.class
        };

        // Create subject selection buttons
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(subject, `add_to_subject_${subject.replace(/ /g, '_')}`)]
        );
        
        // Add "All Subjects" option and cancel button
        subjectButtons.push(
            [Markup.button.callback('📚 All Subjects', 'add_to_all_subjects')],
            [Markup.button.callback('❌ Cancel', 'cancel_add_student')]
        );

        ctx.reply(
            `👤 Student: ${student.name} (${studentId})\n🏫 Class: ${student.class}\n\n` +
            `Select which subject(s) to add this student to:`,
            Markup.inlineKeyboard(subjectButtons)
        );

    } catch (error) {
        console.error('Error processing student ID:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle subject selection
teacherAddStudentScene.action(/^add_to_subject_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();

    try {
        const { studentId, studentName, className } = ctx.session.studentToAdd;
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });

        // Check if relationship already exists
        const existingRelation = await TeacherStudent.findOne({
            teacherId: teacher.teacherId,
            studentId: studentId,
            subject: subject
        });

        if (existingRelation) {
            ctx.reply(`❌ Student ${studentName} is already in your ${subject} class.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Store selected subject and ask for confirmation
        ctx.session.selectedSubject = subject;
        
        ctx.reply(
            `📝 Confirm adding student:\n\n` +
            `👤 Student: ${studentName}\n` +
            `🆔 ID: ${studentId}\n` +
            `🏫 Class: ${className}\n` +
            `📚 Subject: ${subject}\n\n` +
            `Are you sure you want to add this student to your class?`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Yes, Add Student', 'confirm_add_student')],
                [Markup.button.callback('❌ No, Cancel', 'cancel_add_student')]
            ])
        );

    } catch (error) {
        console.error('Error selecting subject:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle "All Subjects" selection
teacherAddStudentScene.action('add_to_all_subjects', async (ctx) => {
    await ctx.answerCbQuery();

    try {
        const { studentId, studentName, className } = ctx.session.studentToAdd;
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });

        // Check which subjects the student is already in
        const existingRelations = await TeacherStudent.find({
            teacherId: teacher.teacherId,
            studentId: studentId
        });

        const existingSubjects = existingRelations.map(rel => rel.subject);
        const subjectsToAdd = teacher.subjects.filter(subject => !existingSubjects.includes(subject));

        if (subjectsToAdd.length === 0) {
            ctx.reply(`❌ Student ${studentName} is already in all your subjects.`, teacherMenu);
            return ctx.scene.leave();
        }

        // Store subjects to add and ask for confirmation
        ctx.session.subjectsToAdd = subjectsToAdd;
        
        ctx.reply(
            `📝 Confirm adding student to all subjects:\n\n` +
            `👤 Student: ${studentName}\n` +
            `🆔 ID: ${studentId}\n` +
            `🏫 Class: ${className}\n` +
            `📚 Subjects: ${subjectsToAdd.join(', ')}\n\n` +
            `Are you sure you want to add this student to all these subjects?`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Yes, Add to All', 'confirm_add_all_subjects')],
                [Markup.button.callback('❌ No, Cancel', 'cancel_add_student')]
            ])
        );

    } catch (error) {
        console.error('Error selecting all subjects:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle single subject confirmation
teacherAddStudentScene.action('confirm_add_student', async (ctx) => {
    await ctx.answerCbQuery();

    try {
        const { studentId, studentName, className } = ctx.session.studentToAdd;
        const subject = ctx.session.selectedSubject;
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });

        // Create the teacher-student relationship
        const newRelation = new TeacherStudent({
            teacherId: teacher.teacherId,
            teacherName: teacher.name,
            studentId: studentId,
            studentName: studentName,
            subject: subject,
            className: className
        });

        await newRelation.save();

        ctx.reply(
            `✅ Successfully added ${studentName} to your ${subject} class!`,
            teacherMenu
        );

    } catch (error) {
        console.error('Error adding student:', error);
        ctx.reply('❌ An error occurred while adding the student.', teacherMenu);
    }
    
    // Clean up session
    delete ctx.session.studentToAdd;
    delete ctx.session.selectedSubject;
    ctx.scene.leave();
});

// Handle all subjects confirmation
teacherAddStudentScene.action('confirm_add_all_subjects', async (ctx) => {
    await ctx.answerCbQuery();

    try {
        const { studentId, studentName, className } = ctx.session.studentToAdd;
        const subjects = ctx.session.subjectsToAdd;
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });

        let addedCount = 0;
        const addedSubjects = [];

        for (const subject of subjects) {
            try {
                const newRelation = new TeacherStudent({
                    teacherId: teacher.teacherId,
                    teacherName: teacher.name,
                    studentId: studentId,
                    studentName: studentName,
                    subject: subject,
                    className: className
                });

                await newRelation.save();
                addedCount++;
                addedSubjects.push(subject);
            } catch (error) {
                if (error.code !== 11000) { // Ignore duplicate key errors
                    console.error(`Error adding student to ${subject}:`, error);
                }
            }
        }

        if (addedCount > 0) {
            ctx.reply(
                `✅ Successfully added ${studentName} to ${addedCount} subject(s):\n` +
                `${addedSubjects.join(', ')}`,
                teacherMenu
            );
        } else {
            ctx.reply(
                `❌ Could not add ${studentName} to any subjects. They may already be in all your classes.`,
                teacherMenu
            );
        }

    } catch (error) {
        console.error('Error adding student to all subjects:', error);
        ctx.reply('❌ An error occurred while adding the student.', teacherMenu);
    }
    
    // Clean up session
    delete ctx.session.studentToAdd;
    delete ctx.session.subjectsToAdd;
    ctx.scene.leave();
});

// Handle cancellation from inline buttons
teacherAddStudentScene.action('cancel_add_student', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Student addition cancelled.', teacherMenu);
    
    // Clean up session
    delete ctx.session.studentToAdd;
    delete ctx.session.selectedSubject;
    delete ctx.session.subjectsToAdd;
    
    ctx.scene.leave();
});

// Handle cancellation from text input
teacherAddStudentScene.hears('❌ Cancel', async (ctx) => {
    ctx.reply('❌ Student addition cancelled.', teacherMenu);
    
    // Clean up session
    delete ctx.session.studentToAdd;
    delete ctx.session.selectedSubject;
    delete ctx.session.subjectsToAdd;
    
    ctx.scene.leave();
});

// Register the scene
stage.register(teacherAddStudentScene);
// Manage Grades Main Scene
const manageGradesScene = new Scenes.BaseScene('manage_grades_scene');

manageGradesScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no subjects assigned. Please add subjects first.', teacherMenu);
            return ctx.scene.leave();
        }

        // Create subject selection buttons
        const subjectButtons = teacher.subjects.map(subject => 
            [Markup.button.callback(subject, `manage_grades_subject_${subject.replace(/ /g, '_')}`)]
        );
        
        subjectButtons.push([Markup.button.callback('❌ Cancel', 'cancel_manage_grades')]);
        
        ctx.reply('📚 Select a subject to manage grades:', 
            Markup.inlineKeyboard(subjectButtons));
    } catch (error) {
        console.error('Error in manage grades scene:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});
// Action handler for selecting a subject
manageGradesScene.action(/select_subject_(.+)/, async (ctx) => {
    try {
        // ✅ The key fix: Answer the callback query immediately, and wrap it
        // in a try...catch to handle rapid clicks without crashing.
        await ctx.answerCbQuery(`Selected: ${ctx.match[1]}`);
    } catch (error) {
        // Log the error but don't crash the bot
        console.error('Error answering callback query:', error);
    }
    
    // Now, perform the rest of the logic
    const subject = ctx.match[1];
    ctx.session.selectedGradeSubject = subject;
    ctx.session.page = 0;
    ctx.session.state = 'selecting_student';
    await showStudentList(ctx);
});
// Handle subject selection
manageGradesScene.action(/^manage_grades_subject_(.+)$/, async (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();
    
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const students = await getStudentsByTeacherAndSubject(teacher.teacherId, subject);
        
        if (students.length === 0) {
            ctx.reply(`❌ No students found for ${subject}.`, teacherMenu);
            return ctx.scene.leave();
        }
        
        // Store subject in session
        ctx.session.gradeSubject = subject;
        
        // Create student buttons (sorted alphabetically)
        const studentButtons = students.map(student => 
            [Markup.button.callback(
                `${student.studentName} (${student.studentId})`, 
                `manage_grades_student_${student.studentId}`
            )]
        );
        
        // Add back and cancel buttons
        studentButtons.push(
            [Markup.button.callback('⬅️ Back to Subjects', 'back_to_grade_subjects')],
            [Markup.button.callback('❌ Cancel', 'cancel_manage_grades')]
        );
        
        ctx.reply(`👥 Students in ${subject}:`, Markup.inlineKeyboard(studentButtons));
    } catch (error) {
        console.error('Error selecting subject for grades:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle student selection
manageGradesScene.action(/^manage_grades_student_(.+)$/, async (ctx) => {
    const studentId = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        const student = await getStudentById(studentId);
        const subject = ctx.session.gradeSubject;
        
        if (!student) {
            ctx.reply('❌ Student not found.', teacherMenu);
            return ctx.scene.leave();
        }
        
        // Store student info in session
        ctx.session.gradeStudentId = studentId;
        ctx.session.gradeStudentName = student.name;
        
        // Get existing grades for this student and subject
        const grades = await getStudentGrades(studentId, subject);
        
        let message = `📊 *Grades for ${student.name} in ${subject}:*\n\n`;
        
        if (grades.length === 0) {
            message += 'No grades recorded yet.\n';
        } else {
            // Calculate average
            const total = grades.reduce((sum, grade) => sum + grade.score, 0);
            const average = total / grades.length;
            
            message += `📈 Average: ${average.toFixed(2)}%\n\n`;
            
            grades.forEach((grade, index) => {
                message += `${index + 1}. ${grade.purpose}: ${grade.score}% (${new Date(grade.date).toLocaleDateString()})\n`;
                if (grade.comments) {
                    message += `   💬 ${grade.comments}\n`;
                }
            });
        }
        
        // Create action buttons
        // Add the Remove Grade button here
const actionButtons = [
  [Markup.button.callback('➕ Add Grade', 'add_grade')],
  [Markup.button.callback('📝 Edit Grades', 'edit_grades')],
  [Markup.button.callback('🗑️ Remove Grade', 'remove_grades')],    // <-- Add this line
  [Markup.button.callback('⬅️ Back to Students', 'back_to_grade_students')],
  [Markup.button.callback('❌ Cancel', 'cancel_manage_grades')]
];

        
        ctx.replyWithMarkdown(message, Markup.inlineKeyboard(actionButtons));
    } catch (error) {
        console.error('Error selecting student for grades:', error);
        ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
        ctx.scene.leave();
    }
});

// Handle add grade action
manageGradesScene.action('add_grade', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('add_grade_scene');
});
manageGradesScene.action('remove_grades', async (ctx) => {
  await ctx.answerCbQuery();
  // Enter a scene or implement remove grade functionality here
  ctx.scene.enter('remove_grade_scene');
});
manageGradesScene.action('edit_grades', async (ctx) => {await ctx.answerCbQuery()
ctx.scene.enter('edit_grades_scene');});

// Handle back to students
manageGradesScene.action('back_to_grade_students', async (ctx) => {
    await ctx.answerCbQuery();
    // Re-enter the scene to show students again
    const subject = ctx.session.gradeSubject;
    ctx.scene.enter('manage_grades_scene');
    
    
});

// Handle back to subjects
manageGradesScene.action('back_to_grade_subjects', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.reenter();
});

// Handle cancel
manageGradesScene.action('cancel_manage_grades', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Grade management cancelled.', teacherMenu);
    ctx.scene.leave();
});

// --- Stepwise Add Grade Scene ---

const addGradeScene = new Scenes.BaseScene('add_grade_scene');

addGradeScene.enter((ctx) => {
  ctx.session.newGrade = {}; // Initialize grade container
  ctx.reply('📝 Adding a new grade.\nPlease enter the *score* (0-100). Type ❌ Cancel to abort.', { parse_mode: 'Markdown' });
});

// Step 1: Score input
addGradeScene.on('text', async (ctx) => {
  const text = ctx.message.text.trim();
  if (text === '❌ Cancel') {
    ctx.reply('❌ Grade addition cancelled.', teacherMenu);
    ctx.scene.leave();
    return;
  }

  if (!ctx.session.newGrade.score) {
    const score = parseInt(text);
    if (isNaN(score) || score < 0 || score > 100) {
      return ctx.reply('❌ Invalid score. Please enter a number between 0 and 100.');
    }
    ctx.session.newGrade.score = score;
    return ctx.reply('Please enter the *purpose* of this grade (quiz, test, assignment, exam, project).', { parse_mode: 'Markdown' });
  }

  // Step 2: Purpose input
  if (!ctx.session.newGrade.purpose) {
    const purpose = text.toLowerCase();
    if (!['quiz', 'test', 'assignment', 'exam', 'project'].includes(purpose)) {
      return ctx.reply('❌ Invalid purpose. Choose from: quiz, test, assignment, exam, project.');
    }
    ctx.session.newGrade.purpose = purpose;
    return ctx.reply('Optional: Enter comments or type "skip" to omit.', { parse_mode: 'Markdown' });
  }

  // Step 3: Comments input (optional)
  if (ctx.session.newGrade.comments === undefined) {
    let comments = text;
    if (comments.toLowerCase() === 'skip') comments = '';
    ctx.session.newGrade.comments = comments;

    // Save the grade
    try {
      const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
      const studentId = ctx.session.gradeStudentId;
      const studentName = ctx.session.gradeStudentName;
      const subject = ctx.session.gradeSubject;
      const { score, purpose, comments } = ctx.session.newGrade;
      const gradeId = await generateUniqueGradeId();

      const newGrade = new Grade({
        gradeId,
        studentId,
        studentName,
        teacherId: teacher.teacherId,
        teacherName: teacher.name,
        subject,
        score,
        purpose,
        comments,
        date: new Date()
      });
      await newGrade.save();

      ctx.replyWithMarkdown(
        `✅ Grade added successfully!\n\n` +
        `*Student:* ${studentName}\n` +
        `*Subject:* ${subject}\n` +
        `*Score:* ${score}%\n` +
        `*Purpose:* ${purpose}\n` +
        `${comments ? `*Comments:* ${comments}\n` : ''}`,
        teacherMenu
      );
    } catch (error) {
      console.error('Error adding grade:', error);
      ctx.reply('❌ An error occurred while adding the grade.', teacherMenu);
    }
    ctx.scene.leave();
  }
});
// --- Remove Grade Scene ---

const removeGradeScene = new Scenes.BaseScene('remove_grade_scene');

removeGradeScene.enter(async (ctx) => {
  try {
    const studentId = ctx.session.gradeStudentId;
    const subject = ctx.session.gradeSubject;
    const grades = await getStudentGrades(studentId, subject);

    if (grades.length === 0) {
      ctx.reply('❌ No grades found to remove.', teacherMenu);
      return ctx.scene.leave();
    }

    const buttons = grades.map(g => 
      [Markup.button.callback(
        `${g.purpose}: ${g.score}% (${new Date(g.date).toLocaleDateString()})`,
        `remove_grade_${g.gradeId}`)]
    );
    buttons.push([Markup.button.callback('⬅️ Cancel', 'cancel_remove_grade')]);

    ctx.replyWithMarkdown(`🗑️ Select a grade to remove for *${ctx.session.gradeStudentName}* in *${subject}:*`, Markup.inlineKeyboard(buttons));
  } catch (error) {
    console.error('Error entering remove grade scene:', error);
    ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
    ctx.scene.leave();
  }
});

// Handle grade removal action
removeGradeScene.action(/^remove_grade_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const gradeId = ctx.match[1];
  try {
    const grade = await Grade.findOne({ gradeId });
    if (!grade) {
      ctx.reply('❌ Grade not found.', teacherMenu);
      return ctx.scene.leave();
    }

    await Grade.deleteOne({ gradeId });
    ctx.replyWithMarkdown(`✅ Grade for *${grade.purpose}* (${grade.score}%) removed successfully.`, teacherMenu);
    ctx.scene.leave();
  } catch (error) {
    console.error('Error removing grade:', error);
    ctx.reply('❌ An error occurred while removing the grade.', teacherMenu);
    ctx.scene.leave();
  }
});

// Cancel handler
removeGradeScene.action('cancel_remove_grade', async (ctx) => {
  await ctx.answerCbQuery();
  ctx.reply('❌ Grade removal cancelled.', teacherMenu);
  ctx.scene.leave();
});

/// --- Enhanced Edit Grades Scene: Stepwise Editing ---

const editGradesScene = new Scenes.BaseScene('edit_grades_scene');
const editGradeProcessScene = new Scenes.BaseScene('edit_grade_process_scene');

editGradesScene.enter(async (ctx) => {
  try {
    const studentId = ctx.session.gradeStudentId;
    const subject = ctx.session.gradeSubject;
    const studentName = ctx.session.gradeStudentName;
    const grades = await getStudentGrades(studentId, subject);

    if (grades.length === 0) {
      ctx.reply('❌ No grades found to edit.', teacherMenu);
      return ctx.scene.leave();
    }

    const gradeButtons = grades.map(grade =>
      [Markup.button.callback(
        `${grade.purpose}: ${grade.score}% (${new Date(grade.date).toLocaleDateString()})`,
        `edit_grade_${grade.gradeId}`
      )]
    );
    gradeButtons.push(
      [Markup.button.callback('⬅️ Back', 'back_to_grade_management')],
      [Markup.button.callback('❌ Cancel', 'cancel_edit_grades')]
    );

    ctx.replyWithMarkdown(
      `📝 Select a grade to edit for *${studentName}* in *${subject}:*`,
      Markup.inlineKeyboard(gradeButtons)
    );
  } catch (error) {
    console.error('Error in edit grades scene:', error);
    ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
    ctx.scene.leave();
  }
});

editGradesScene.action(/^edit_grade_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const gradeId = ctx.match[1];
  try {
    const grade = await Grade.findOne({ gradeId });
    if (!grade) {
      ctx.reply('❌ Grade not found.', teacherMenu);
      return ctx.scene.leave();
    }
    // Store current grade in session for editing
    ctx.session.editingGrade = {
      gradeId: grade.gradeId,
      score: grade.score,
      purpose: grade.purpose,
      comments: grade.comments || ''
    };
    ctx.reply(`📝 Current score: ${grade.score}\nPlease enter the new score (0-100). Type ❌ Cancel to abort.`);
    ctx.scene.enter('edit_grade_process_scene');
  } catch (error) {
    console.error('Error selecting grade for editing:', error);
    ctx.reply('❌ An error occurred. Please try again.', teacherMenu);
    ctx.scene.leave();
  }
});

// Remove the incorrect text handler from editGradesScene
// editGradesScene.on('text', async (ctx) => { ... }); // REMOVE THIS

// Handle back to grade management
editGradesScene.action('back_to_grade_management', async (ctx) => {
  await ctx.answerCbQuery();
  ctx.scene.enter('manage_grades_scene');
});

// Handle cancel
editGradesScene.action('cancel_edit_grades', async (ctx) => {
  await ctx.answerCbQuery();
  ctx.reply('❌ Grade editing cancelled.', teacherMenu);
  ctx.scene.leave();
});

// --- Edit Grade Process Scene ---
editGradeProcessScene.enter((ctx) => {
  // This scene handles the step-by-step editing process
  ctx.reply('📝 Please enter the new score (0-100). Type ❌ Cancel to abort.');
});

editGradeProcessScene.on('text', async (ctx) => {
  const text = ctx.message.text.trim();
  
  if (text === '❌ Cancel') {
    ctx.reply('❌ Grade editing cancelled.', teacherMenu);
    return ctx.scene.leave();
  }

  // Step 1: Score input
  if (!ctx.session.newScore) {
    const score = parseInt(text);
    if (isNaN(score) || score < 0 || score > 100) {
      return ctx.reply('❌ Invalid score. Please enter a number between 0 and 100.');
    }
    ctx.session.newScore = score;
    return ctx.reply('Please enter the purpose of this grade (quiz, test, assignment, exam, project).');
  }

  // Step 2: Purpose input
  if (!ctx.session.newPurpose) {
    const purpose = text.toLowerCase();
    if (!['quiz', 'test', 'assignment', 'exam', 'project'].includes(purpose)) {
      return ctx.reply('❌ Invalid purpose. Choose from: quiz, test, assignment, exam, project.');
    }
    ctx.session.newPurpose = purpose;
    return ctx.reply('Optional: Enter comments or type "skip" to omit.');
  }

  // Step 3: Comments input (optional)
  if (ctx.session.newComments === undefined) {
    let comments = text;
    if (comments.toLowerCase() === 'skip') comments = '';
    ctx.session.newComments = comments;

    // Save the updated grade
    try {
      const { gradeId } = ctx.session.editingGrade;
      const { newScore, newPurpose, newComments } = ctx.session;

      const grade = await Grade.findOne({ gradeId });
      if (!grade) {
        ctx.reply('❌ Grade not found.', teacherMenu);
        return ctx.scene.leave();
      }

      grade.score = newScore;
      grade.purpose = newPurpose;
      grade.comments = newComments;
      grade.date = new Date();
      await grade.save();

      ctx.replyWithMarkdown(
        `✅ Grade updated successfully!\n\n` +
        `*Student:* ${grade.studentName}\n` +
        `*Subject:* ${grade.subject}\n` +
        `*Score:* ${newScore}%\n` +
        `*Purpose:* ${newPurpose}\n` +
        `${newComments ? `*Comments:* ${newComments}\n` : ''}`,
        teacherMenu
      );

    } catch (error) {
      console.error('Error updating grade:', error);
      ctx.reply('❌ An error occurred while updating the grade.', teacherMenu);
    }

    // Clean up session
    delete ctx.session.newScore;
    delete ctx.session.newPurpose;
    delete ctx.session.newComments;
    delete ctx.session.editingGrade;
    
    ctx.scene.leave();
  }
});

// Handle cancel in process scene
editGradeProcessScene.hears('❌ Cancel', async (ctx) => {
  // Clean up session
  delete ctx.session.newScore;
  delete ctx.session.newPurpose;
  delete ctx.session.newComments;
  delete ctx.session.editingGrade;
  
  ctx.reply('❌ Grade editing cancelled.', teacherMenu);
  ctx.scene.leave();
});

// Register the scenes
stage.register(editGradesScene);
stage.register(editGradeProcessScene);
stage.register(manageGradesScene);
stage.register(addGradeScene);
stage.register(removeGradeScene);
stage.register(editGradesScene);
stage.register(editGradeProcessScene);



// Teacher Upload Student List Scene

// Contact Admins Scene
const contactAdminsScene = new Scenes.BaseScene('contact_admins_scene');

contactAdminsScene.enter(async (ctx) => {
    try {
        // Get all admins except the current user
        const admins = await User.find({ role: 'admin' });
        const filteredAdmins = admins.filter(admin => admin.telegramId !== ctx.from.id.toString());
        
        if (filteredAdmins.length === 0) {
            ctx.reply('❌ No other admins found to contact.', adminMenu);
            return ctx.scene.leave();
        }
        
        // Create inline buttons for each admin
        const adminButtons = filteredAdmins.map(admin => 
            [Markup.button.callback(
                `${admin.name} (ID: ${admin.telegramId})`, 
                `select_admin_${admin.telegramId}`
            )]
        );
        
        // Add cancel button
        adminButtons.push([Markup.button.callback('❌ Cancel', 'cancel_contact_admins')]);
        
        ctx.reply('👑 Select an admin to contact:', Markup.inlineKeyboard(adminButtons));
    } catch (error) {
        console.error('Error retrieving admins:', error);
        ctx.reply('❌ An error occurred while retrieving admins.', adminMenu);
        ctx.scene.leave();
    }
});

// Handle admin selection
contactAdminsScene.action(/^select_admin_(\d+)$/, async (ctx) => {
    const adminTelegramId = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        const admin = await getUserById(adminTelegramId);
        if (!admin) {
            ctx.reply('❌ Admin not found.', adminMenu);
            return ctx.scene.leave();
        }
        
        // Store recipient info in session
        ctx.session.recipientId = adminTelegramId;
        ctx.session.recipientName = admin.name;
        
        ctx.reply(`📬 You are now messaging **${admin.name}** (ID: ${adminTelegramId}).\n📤 Send any message (text, photo, video, document, audio, voice).`, Markup.keyboard([['❌ Cancel']]).resize());
        ctx.scene.enter('send_message_to_admin_scene');
    } catch (error) {
        console.error('Error selecting admin:', error);
        ctx.reply('❌ An error occurred.', adminMenu);
        ctx.scene.leave();
    }
});

// Handle cancel action
contactAdminsScene.action('cancel_contact_admins', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Contact admins cancelled.', adminMenu);
    ctx.scene.leave();
});
/// Admin-only: Contact Parent by Telegram ID
const contactParentAdminScene = new Scenes.BaseScene('contact_parent_admin_scene');

contactParentAdminScene.enter((ctx) => {
  const cancelKeyboard = Markup.keyboard([
    ['❌ Cancel']
  ]).resize();

  ctx.reply(
    '🆔 Please enter the *Telegram ID* of the parent you want to contact.\n\n' +
    '🔍 Tip: Use /search to find parents by name if you don’t know the ID.',
    cancelKeyboard
  );
});

// Handle Cancel
contactParentAdminScene.hears('❌ Cancel', async (ctx) => {
  ctx.session.recipientId = null;
  ctx.session.recipientName = null;
  await ctx.reply('❌ Operation cancelled.', adminMenu);
  return ctx.scene.leave();
});

// Handle Parent ID input
contactParentAdminScene.on('text', async (ctx) => {
  const input = ctx.message.text.trim();

  if (input === '❌ Cancel') {
    return ctx.scene.reenter(); // Triggers the cancel handler
  }

  // Validate numeric ID
  if (!/^\d+$/.test(input)) {
    return ctx.reply(
      '❌ Invalid Telegram ID. Please enter a numeric ID.\n\n' +
      '💡 Use /search to look up parents by name.'
    );
  }

  const parentId = parseInt(input, 10);

  try {
    const parent = await getUserById(parentId);
    if (!parent || parent.role !== 'parent') {
      return ctx.reply(
        '❌ No parent found with that ID.\n\n' +
        '💡 Try using /search to find the parent by name.'
      );
    }

    // Store recipient
    ctx.session.recipientId = parentId;
    ctx.session.recipientName = parent.name;

    const replyKeyboard = Markup.keyboard([
      ['❌ Cancel']
    ]).resize();

    ctx.reply(
      `📬 You are now messaging **${parent.name}** (ID: ${parentId}).\n` +
      '📤 Send any message (text, photo, video, document, audio, voice).',
      replyKeyboard
    );
    ctx.scene.enter('send_message_to_parent_admin_scene');
  } catch (error) {
    console.error('Error finding parent by ID:', error);
    ctx.reply('❌ An error occurred while retrieving the parent.');
  }
});

// Send Message to Admin Scene
const sendMessageToAdminScene = new Scenes.BaseScene('send_message_to_admin_scene');

// Handle Cancel
sendMessageToAdminScene.hears('❌ Cancel', async (ctx) => {
    ctx.session.recipientId = null;
    ctx.session.recipientName = null;
    await ctx.reply('❌ Message cancelled.', adminMenu);
    return ctx.scene.leave();
});

// Handle all message types
sendMessageToAdminScene.on(['text', 'photo', 'video', 'document', 'audio', 'voice'], async (ctx) => {
    const recipientId = ctx.session.recipientId;
    if (!recipientId) {
        await ctx.reply('❌ Recipient not set. Starting over.', adminMenu);
        return ctx.scene.leave();
    }

    const senderName = ctx.from.first_name || ctx.from.username || 'Admin';

    try {
        if (ctx.message.text) {
            const text = ctx.message.text.trim();
            await ctx.telegram.sendMessage(
                recipientId,
                `📢 *Message from Admin ${senderName}:*\n${text}`,
                { parse_mode: 'Markdown' }
            );
        } 
        else if (ctx.message.photo) {
            const photo = ctx.message.photo[ctx.message.photo.length - 1];
            const caption = ctx.message.caption
                ? `📢 *Message from Admin ${senderName}:*\n${ctx.message.caption}`
                : `📢 Message from Admin ${senderName}`;
            await ctx.telegram.sendPhoto(recipientId, photo.file_id, {
                caption,
                parse_mode: 'Markdown'
            });
        } 
        else if (ctx.message.video) {
            const caption = ctx.message.caption
                ? `📢 *Message from Admin ${senderName}:*\n${ctx.message.caption}`
                : `📢 Message from Admin ${senderName}`;
            await ctx.telegram.sendVideo(recipientId, ctx.message.video.file_id, {
                caption,
                parse_mode: 'Markdown'
            });
        } 
        else if (ctx.message.document) {
            const caption = ctx.message.caption
                ? `📢 *Message from Admin ${senderName}:*\n${ctx.message.caption}`
                : `📢 Message from Admin ${senderName}`;
            await ctx.telegram.sendDocument(recipientId, ctx.message.document.file_id, {
                caption,
                parse_mode: 'Markdown'
            });
        } 
        else if (ctx.message.audio) {
            const caption = ctx.message.caption
                ? `📢 *Message from Admin ${senderName}:*\n${ctx.message.caption}`
                : `📢 Message from Admin ${senderName}`;
            await ctx.telegram.sendAudio(recipientId, ctx.message.audio.file_id, {
                caption,
                parse_mode: 'Markdown'
            });
        } 
        else if (ctx.message.voice) {
            await ctx.telegram.sendVoice(recipientId, ctx.message.voice.file_id);
            await ctx.telegram.sendMessage(
                recipientId,
                `🗨️ *Voice message from Admin ${senderName}*`,
                { parse_mode: 'Markdown' }
            );
        }

        await ctx.reply('✅ Message sent successfully!', adminMenu);
    } catch (error) {
        if (error.response?.error_code === 403) {
            await ctx.reply(
                '❌ Failed to send message. The admin may have blocked the bot.',
                adminMenu
            );
        } else {
            console.error('Error sending message to admin:', error);
            await ctx.reply('❌ Failed to send message. Please try again later.', adminMenu);
        }
    } finally {
        ctx.session.recipientId = null;
        ctx.session.recipientName = null;
        ctx.scene.leave();
    }
});

// Fallback for unsupported types
sendMessageToAdminScene.on('message', (ctx) => {
    ctx.reply('⚠️ Unsupported content. Please send text, photo, video, document, audio, or voice.');
});
stage.register(contactAdminsScene);
stage.register(sendMessageToAdminScene);

// Send any message/media to parent — includes admin name
const sendMessageToParentAdminScene = new Scenes.BaseScene('send_message_to_parent_admin_scene');

// Handle Cancel
sendMessageToParentAdminScene.hears('❌ Cancel', async (ctx) => {
  ctx.session.recipientId = null;
  ctx.session.recipientName = null;
  await ctx.reply('❌ Message cancelled.', adminMenu);
  return ctx.scene.leave();
});

// Handle all message types
sendMessageToParentAdminScene.on(['text', 'photo', 'video', 'document', 'audio', 'voice'], async (ctx) => {
  const recipientId = ctx.session.recipientId;
  if (!recipientId) {
    await ctx.reply('❌ Recipient not set. Starting over.', adminMenu);
    return ctx.scene.leave();
  }

  const adminName = ctx.from.first_name || ctx.from.username || 'Admin';

  try {
    if (ctx.message.text) {
      const text = ctx.message.text.trim();
      await ctx.telegram.sendMessage(
        recipientId,
        `📢 *Message from Admin (${adminName}):*\n${text}`,
        { parse_mode: 'Markdown' }
      );
    } 
    else if (ctx.message.photo) {
      const photo = ctx.message.photo[ctx.message.photo.length - 1];
      const caption = ctx.message.caption
        ? `📢 *Message from Admin (${adminName})*:\n${ctx.message.caption}`
        : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendPhoto(recipientId, photo.file_id, {
        caption,
        parse_mode: 'Markdown'
      });
    } 
    else if (ctx.message.video) {
      const caption = ctx.message.caption
        ? `📢 *Message from Admin (${adminName})*:\n${ctx.message.caption}`
        : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendVideo(recipientId, ctx.message.video.file_id, {
        caption,
        parse_mode: 'Markdown'
      });
    } 
    else if (ctx.message.document) {
      const caption = ctx.message.caption
        ? `📢 *Message from Admin (${adminName})*:\n${ctx.message.caption}`
        : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendDocument(recipientId, ctx.message.document.file_id, {
        caption,
        parse_mode: 'Markdown'
      });
    } 
    else if (ctx.message.audio) {
      const caption = ctx.message.caption
        ? `📢 *Message from Admin (${adminName})*:\n${ctx.message.caption}`
        : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendAudio(recipientId, ctx.message.audio.file_id, {
        caption,
        parse_mode: 'Markdown'
      });
    } 
    else if (ctx.message.voice) {
      await ctx.telegram.sendVoice(recipientId, ctx.message.voice.file_id);
      await ctx.telegram.sendMessage(
        recipientId,
        `🗨️ *Voice message from Admin (${adminName})*`,
        { parse_mode: 'Markdown' }
      );
    }

    await ctx.reply('✅ Message sent successfully!', adminMenu);
  } catch (error) {
    if (error.response?.error_code === 403) {
      await ctx.reply(
        '❌ Failed to send message. The parent may have blocked the bot.',
        adminMenu
      );
    } else {
      console.error('Error sending message to parent:', error);
      await ctx.reply('❌ Failed to send message. Please try again later.', adminMenu);
    }
  } finally {
    ctx.session.recipientId = null;
    ctx.session.recipientName = null;
    ctx.scene.leave();
  }
});

// Fallback for unsupported types
sendMessageToParentAdminScene.on('message', (ctx) => {
  ctx.reply('⚠️ Unsupported content. Please send text, photo, video, document, audio, or voice.');
});

stage.register(sendMessageToParentAdminScene);
stage.register(contactParentAdminScene);

// Contact Teacher Scene - Admin picks teacher to contact
const contactTeacherScene = new Scenes.BaseScene('contact_teacher_scene');

contactTeacherScene.enter(async (ctx) => {
  // List all teachers to select
  try {
    const teachers = await Teacher.find().sort({ name: 1 });
    if (teachers.length === 0) {
      ctx.reply('❌ No teachers found.');
      return ctx.scene.leave();
    }
    const teacherButtons = teachers.map((teacher) =>
      [Markup.button.callback(`${teacher.name} (ID: ${teacher.teacherId})`, `select_contact_teacher_${teacher.teacherId}`)]
    );
    teacherButtons.push([Markup.button.callback('❌ Cancel', 'cancel_contact_teacher')]);
    ctx.reply('🧑🏫 Select a teacher to contact:', Markup.inlineKeyboard(teacherButtons));
  } catch (error) {
    console.error('Error fetching teachers in contactTeacherScene:', error);
    ctx.reply('❌ An error occurred. Please try again later.');
    ctx.scene.leave();
  }
});

contactTeacherScene.action(/^select_contact_teacher_(.+)$/, async (ctx) => {
  const teacherId = ctx.match[1];
  await ctx.answerCbQuery();
  ctx.session.contactTeacherId = teacherId;
  ctx.reply('📝 Please send the message or media you want to send to the teacher.');
  ctx.scene.enter('send_contact_teacher_message_scene');
});

contactTeacherScene.action('cancel_contact_teacher', async (ctx) => {
  await ctx.answerCbQuery();
  ctx.reply('❌ Contact cancelled.', adminMenu);
  ctx.scene.leave();
});

// Scene for sending message/media to selected teacher
const sendContactTeacherMessageScene = new Scenes.BaseScene('send_contact_teacher_message_scene');

sendContactTeacherMessageScene.on(['text', 'photo', 'video', 'document', 'audio', 'voice'], async (ctx) => {
  const teacherId = ctx.session.contactTeacherId;
  if (!teacherId) {
    ctx.reply('❌ No teacher selected. Please start again.');
    return ctx.scene.leave();
  }
  try {
    const teacher = await getTeacherById(teacherId);
    if (!teacher || !teacher.telegramId) {
      ctx.reply('❌ Teacher not found or not linked with Telegram.');
      return ctx.scene.leave();
    }
    const adminName = ctx.from.first_name || ctx.from.username || 'Admin';

    // Determine message content type
    if (ctx.message.text) {
      // Text message
      const textToSend = `📢 *Message from Admin (${adminName}):*\n${ctx.message.text.trim()}`;
      await ctx.telegram.sendMessage(teacher.telegramId, textToSend, { parse_mode: 'Markdown' });
    } else if (ctx.message.photo) {
      // Photo (send highest resolution)
      const photoArray = ctx.message.photo;
      const highestResPhoto = photoArray[photoArray.length - 1];
      const caption = ctx.message.caption ? `📢 *Message from Admin (${adminName}):*\n${ctx.message.caption}` : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendPhoto(teacher.telegramId, highestResPhoto.file_id, { caption, parse_mode: 'Markdown' });
    } else if (ctx.message.video) {
      const caption = ctx.message.caption ? `📢 *Message from Admin (${adminName}):*\n${ctx.message.caption}` : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendVideo(teacher.telegramId, ctx.message.video.file_id, { caption, parse_mode: 'Markdown' });
    } else if (ctx.message.document) {
      const caption = ctx.message.caption ? `📢 *Message from Admin (${adminName}):*\n${ctx.message.caption}` : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendDocument(teacher.telegramId, ctx.message.document.file_id, { caption, parse_mode: 'Markdown' });
    } else if (ctx.message.audio) {
      const caption = ctx.message.caption ? `📢 *Message from Admin (${adminName}):*\n${ctx.message.caption}` : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendAudio(teacher.telegramId, ctx.message.audio.file_id, { caption, parse_mode: 'Markdown' });
    } else if (ctx.message.voice) {
      const caption = ctx.message.caption ? `📢 *Message from Admin (${adminName}):*\n${ctx.message.caption}` : `📢 Message from Admin (${adminName})`;
      await ctx.telegram.sendVoice(teacher.telegramId, ctx.message.voice.file_id, { caption, parse_mode: 'Markdown' });
    } else {
      ctx.reply('❌ Unsupported message type. Please send text, photo, video, document, audio, or voice.');
      return;
    }
    ctx.reply('✅ Message sent to the teacher.', adminMenu);
  } catch (error) {
    if (error.response && error.response.error_code === 403) {
      ctx.reply('❌ Cannot send message, the teacher may have blocked the bot.');
    } else {
      console.error('Error sending contact teacher message:', error);
      ctx.reply('❌ An error occurred while sending the message.');
    }
  } finally {
    ctx.session.contactTeacherId = null;
    ctx.scene.leave();
  }
});

sendContactTeacherMessageScene.on('message', (ctx) => {
  ctx.reply('❌ Please send a valid message type: text, photo, video, document, audio, or voice.');
});

stage.register(contactTeacherScene);
stage.register(sendContactTeacherMessageScene);

/// Remove Teacher Scene - Enhanced with complete data cleanup including userSchema teacher data
const removeTeacherScene = new Scenes.BaseScene('remove_teacher_scene');

removeTeacherScene.enter(async (ctx) => {
    try {
        // Get all registered teachers
        const teachers = await Teacher.find().sort({ name: 1 });
        
        if (teachers.length === 0) {
            ctx.reply('❌ No teachers found to remove.', {
                reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
            });
            return ctx.scene.leave();
        }
        
        // Create inline buttons for each teacher
        const teacherButtons = teachers.map(teacher => 
            [Markup.button.callback(
                `${teacher.name} (ID: ${teacher.teacherId})`, 
                `remove_teacher_${teacher.teacherId}`
            )]
        );
        
        // Add cancel button
        teacherButtons.push([Markup.button.callback('❌ Cancel', 'cancel_remove_teacher')]);
        
        ctx.reply('🧑🏫 Select a teacher to remove:', Markup.inlineKeyboard(teacherButtons));
    } catch (error) {
        console.error('Error retrieving teachers for removal:', error);
        ctx.reply('❌ An error occurred while retrieving teachers.', {
            reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
        });
        ctx.scene.leave();
    }
});

// Handle teacher selection for removal
removeTeacherScene.action(/^remove_teacher_(.+)$/, async (ctx) => {
    const teacherId = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        const teacher = await getTeacherById(teacherId);
        if (!teacher) {
            ctx.reply('❌ Teacher not found.', {
                reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
            });
            return ctx.scene.leave();
        }
        
        // Store teacher info in session for confirmation
        ctx.session.teacherToRemove = teacher;
        
        // Get statistics for confirmation message
        const studentRelationsCount = await TeacherStudent.countDocuments({ teacherId });
        const gradesCount = await Grade.countDocuments({ teacherId });
        
        // Check if teacher has user schema data
        let userSchemaData = 0;
        if (teacher.telegramId) {
            const user = await getUserById(teacher.telegramId);
            if (user) {
                // Count teacher-specific data in user schema
                if (user.role === 'teacher') userSchemaData++;
                if (user.subjects && user.subjects.length > 0) userSchemaData++;
                if (user.adminId !== undefined && user.adminId !== null) userSchemaData++;
            }
        }
        
        // Ask for confirmation with detailed information
        ctx.replyWithMarkdown(
            `⚠️ *Confirm Teacher Removal*\n\n` +
            `*Teacher Details:*\n` +
            `• Name: ${teacher.name}\n` +
            `• ID: ${teacher.teacherId}\n` +
            `• Subjects: ${teacher.subjects.join(', ') || 'None'}\n` +
            `• Telegram ID: ${teacher.telegramId || 'Not linked'}\n\n` +
            `*Associated Data:*\n` +
            `• Student Relationships: ${studentRelationsCount}\n` +
            `• Grades Assigned: ${gradesCount}\n` +
            `• User Schema Data: ${userSchemaData} fields\n\n` +
            `*This action will permanently delete:*\n` +
            `• Teacher profile\n` +
            `• All student-teacher relationships\n` +
            `• All grades assigned by this teacher\n` +
            `• Teacher login credentials\n` +
            `• Teacher data in user schema\n\n` +
            `*This action cannot be undone!*\n\n` +
            `Are you sure you want to proceed?`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✅ Yes, Remove Everything', `confirm_remove_${teacherId}`)],
                [Markup.button.callback('❌ No, Cancel', 'cancel_remove_teacher')]
            ])
        );
    } catch (error) {
        console.error('Error in remove teacher scene:', error);
        ctx.reply('❌ An error occurred.', {
            reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
        });
        ctx.scene.leave();
    }
});

// Handle confirmation of removal with complete data cleanup including userSchema
removeTeacherScene.action(/^confirm_remove_(.+)$/, async (ctx) => {
    const teacherId = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        const teacher = await getTeacherById(teacherId);
        if (!teacher) {
            ctx.reply('❌ Teacher not found.', {
                reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
            });
            return ctx.scene.leave();
        }
        
        const teacherName = teacher.name;
        const teacherTelegramId = teacher.telegramId;
        
        // Start transaction-like cleanup process
        let deletedRelations = 0;
        let deletedGrades = 0;
        let userSchemaCleaned = false;
        let userAccountHandled = false;
        
        try {
            // 1. Remove all teacher-student relationships
            const relationsResult = await TeacherStudent.deleteMany({ teacherId });
            deletedRelations = relationsResult.deletedCount;
            
            // 2. Remove all grades assigned by this teacher
            const gradesResult = await Grade.deleteMany({ teacherId });
            deletedGrades = gradesResult.deletedCount;
            
            // 3. Remove teacher login credentials
            await TeacherLogin.deleteOne({ teacherId });
            
            // 4. Remove the teacher record
            await Teacher.deleteOne({ teacherId });
            
            // 5. Clean up user schema data for this teacher
            if (teacherTelegramId) {
                const user = await getUserById(teacherTelegramId);
                if (user) {
                    userAccountHandled = true;
                    
                    // Remove all teacher-specific data from user schema
                    if (user.role === 'teacher') {
                        user.role = 'user'; // Downgrade to regular user
                    }
                    
                    // Clear teacher-specific fields
                    user.subjects = []; // Clear subjects array
                    
                    // Clear adminId if it exists (shouldn't for teachers, but just in case)
                    if (user.adminId !== undefined && user.adminId !== null) {
                        user.adminId = null;
                    }
                    
                    // Clear any other teacher-specific fields that might exist
                    if (user.teacherId !== undefined) {
                        user.teacherId = undefined;
                    }
                    
                    await user.save();
                    userSchemaCleaned = true;
                    
                    // If user has no other purpose, consider deleting completely
                    // (This is optional - keeping the user as 'user' role might be better)
                }
            }
            
            // Send success message with cleanup summary
            ctx.replyWithMarkdown(
                `✅ *Teacher successfully removed!*\n\n` +
                `🧑🏫 *Teacher:* ${teacherName}\n` +
                `🆔 *ID:* ${teacherId}\n\n` +
                `🗑️ *Data Cleanup Summary:*\n` +
                `• Student relationships removed: ${deletedRelations}\n` +
                `• Grades removed: ${deletedGrades}\n` +
                `• Login credentials removed: ✅\n` +
                `• Teacher profile removed: ✅\n` +
                `• User schema data cleaned: ${userSchemaCleaned ? '✅' : '❌'}\n` +
                `• User account handled: ${userAccountHandled ? '✅' : 'N/A'}\n\n` +
                `*All associated data has been permanently deleted or cleaned.*`,
                {
                    reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
                }
            );
            
        } catch (cleanupError) {
            console.error('Error during teacher data cleanup:', cleanupError);
            ctx.reply(
                `⚠️ *Partial Removal Completed*\n\n` +
                `Teacher ${teacherName} was removed, but some data cleanup failed. ` +
                `Please contact system administrator to verify complete removal.\n\n` +
                `Cleanup status:\n` +
                `• Teacher profile: ✅\n` +
                `• User schema: ${userSchemaCleaned ? '✅' : '❌'}\n` +
                `• Error: ${cleanupError.message}`,
                {
                    reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
                }
            );
        }
        
    } catch (error) {
        console.error('Error removing teacher:', error);
        ctx.reply('❌ An error occurred while removing the teacher.', {
            reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
        });
    }
    
    // Clean up session
    delete ctx.session.teacherToRemove;
    ctx.scene.leave();
});

// Handle cancellation
removeTeacherScene.action('cancel_remove_teacher', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Teacher removal cancelled.', {
        reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
    });
    
    // Clean up session
    delete ctx.session.teacherToRemove;
    ctx.scene.leave();
});

// Register the scene
stage.register(removeTeacherScene);
// View Students by Grade Scene - Shows available classes from uploads with Telegram info
const viewStudentsByGradeScene = new Scenes.BaseScene('view_students_by_grade_scene');
viewStudentsByGradeScene.enter(async (ctx) => {
    try {
        // Get all available classes from uploaded files
        const availableClasses = await getUniqueClasses();
        
        if (availableClasses.length === 0) {
            ctx.reply('❌ No classes found from uploaded lists. Please upload a student list first.');
            return ctx.scene.leave();
        }
        
        // Create inline buttons for each class
        const classButtons = availableClasses.map(className => 
            [Markup.button.callback(
                className, 
                `view_class_${className.replace(/\s+/g, '_')}`
            )]
        );
        
        // Add cancel button
        classButtons.push([Markup.button.callback('❌ Cancel', 'cancel_view_students')]);
        
        ctx.reply('🎓 Select a class to view students:', Markup.inlineKeyboard(classButtons));
    } catch (error) {
        console.error('Error retrieving classes:', error);
        ctx.reply('❌ An error occurred while retrieving classes.');
        ctx.scene.leave();
    }
});

// Handle class selection - generate detailed list with Telegram info
viewStudentsByGradeScene.action(/^view_class_(.+)$/, async (ctx) => {
    const className = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();
    
    try {
        const students = await Student.find({ class: new RegExp(className, 'i') }).sort({ name: 1 });
        if (students.length === 0) {
            ctx.reply(`❌ No students found in ${className}.`);
            return ctx.scene.leave();
        }
        
        // Get parent information for all students
        const studentPromises = students.map(async (student) => {
            let parentInfo = {
                telegramId: 'Not linked',
                username: 'N/A',
                name: 'N/A'
            };
            
            if (student.parentId) {
                const parentUser = await getUserById(student.parentId);
                if (parentUser) {
                    parentInfo = {
                        telegramId: parentUser.telegramId,
                        username: parentUser.username || 'N/A',
                        name: parentUser.name || 'N/A'
                    };
                } else {
                    parentInfo = {
                        telegramId: student.parentId,
                        username: 'Not found',
                        name: 'Not found'
                    };
                }
            }
            
            return { 
                ...student.toObject(), 
                parentInfo 
            };
        });
        
        const studentsWithParentInfo = await Promise.all(studentPromises);
        
        // Calculate column widths for proper formatting
        const maxNameLength = Math.max(...studentsWithParentInfo.map(s => s.name.length), 10);
        const maxParentNameLength = Math.max(...studentsWithParentInfo.map(s => s.parentInfo.name.length), 8);
        
        // Generate detailed list with Telegram information
        let fileContent = `DETAILED STUDENT LIST - ${className.toUpperCase()}\n`;
        fileContent += '='.repeat(120) + '\n';
        fileContent += `${'STUDENT NAME'.padEnd(maxNameLength)} - STUDENT ID - ${'PARENT NAME'.padEnd(maxParentNameLength)} - TELEGRAM ID - TELEGRAM USERNAME\n`;
        fileContent += '-'.repeat(maxNameLength) + ' - ' + '-'.repeat(10) + ' - ' + 
                      '-'.repeat(maxParentNameLength) + ' - ' + '-'.repeat(10) + ' - ' + '-'.repeat(15) + '\n';
        
        studentsWithParentInfo.forEach(student => {
            const paddedStudentName = student.name.padEnd(maxNameLength);
            const paddedParentName = student.parentInfo.name.padEnd(maxParentNameLength);
            
            fileContent += `${paddedStudentName} - ${student.studentId} - ${paddedParentName} - ${student.parentInfo.telegramId} - ${student.parentInfo.username}\n`;
        });
        
        fileContent += `\nTotal: ${studentsWithParentInfo.length} students\n`;
        fileContent += `Generated on: ${new Date().toLocaleString()}\n`;
        fileContent += 'Generated by School System Bot';
        
        const tempDir = './temp_exports';
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        const filename = `students_detailed_${className.replace(/\s+/g, '_')}.txt`;
        const tempPath = path.join(tempDir, filename);
        fs.writeFileSync(tempPath, fileContent);
        
        await ctx.replyWithDocument({
            source: tempPath,
            filename: filename,
            caption: `📋 Detailed student list for ${className} (${studentsWithParentInfo.length} students)`
        });
        
        // Clean up
        if (fs.existsSync(tempPath)) {
            fs.unlinkSync(tempPath);
        }
        
    } catch (error) {
        console.error('Error viewing students:', error);
        ctx.reply('❌ An error occurred while retrieving students.');
    }
    ctx.scene.leave();
});

// Handle cancel action
viewStudentsByGradeScene.action('cancel_view_students', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ View students cancelled.', {
        reply_markup: { keyboard: studentManagementMenu.reply_markup.keyboard, resize_keyboard: true }
    });
    ctx.scene.leave();
});



stage.register(viewStudentsByGradeScene);
// Export IDs Scene
const exportIdsScene = new Scenes.BaseScene('export_ids_scene');

exportIdsScene.enter(async (ctx) => {
    try {
        // Get all processed uploads with class assignments
        const uploadedFiles = await UploadedFile.find({ 
            processed: true, 
            classAssigned: { $exists: true, $ne: null } 
        }).sort({ uploadDate: -1 });
        
        if (uploadedFiles.length === 0) {
            ctx.reply('❌ No processed class lists found. Please upload student lists first.');
            return ctx.scene.leave();
        }
        
        // Create inline buttons for each class
        const classButtons = uploadedFiles.map(file => 
            [Markup.button.callback(
                `${file.classAssigned} (${new Date(file.uploadDate).toLocaleDateString()})`, 
                `export_ids_${file.id}`
            )]
        );
        
        // Add cancel button
        classButtons.push([Markup.button.callback('❌ Cancel', 'cancel_export')]);
        
        ctx.reply('📊 Select a class to export student IDs:', Markup.inlineKeyboard(classButtons));
    } catch (error) {
        console.error('Error retrieving uploaded files:', error);
        ctx.reply('❌ An error occurred while retrieving class lists.');
        ctx.scene.leave();
    }
});

// Handle class selection
exportIdsScene.action(/^export_ids_(.+)$/, async (ctx) => {
    const fileId = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        // Get the uploaded file record
        const uploadedFile = await UploadedFile.findOne({ id: fileId });
        if (!uploadedFile) {
            ctx.reply('❌ Class list not found.');
            return ctx.scene.leave();
        }
        
        // Get all students from this class
        const students = await Student.find({ 
            class: uploadedFile.classAssigned 
        }).sort({ name: 1 });
        
        if (students.length === 0) {
            ctx.reply(`❌ No students found in class "${uploadedFile.classAssigned}".`);
            return ctx.scene.leave();
        }
        
        // Create a text file with only ID numbers
        const idList = students.map(student => student.studentId).join('\n');
        const fileName = `student_ids_${uploadedFile.classAssigned.replace(/\s+/g, '_')}.txt`;
        
        // Create temporary file
        const tempDir = './temp_exports';
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        const tempPath = path.join(tempDir, fileName);
        fs.writeFileSync(tempPath, idList);
        
        // Send the file
        await ctx.replyWithDocument({
            source: tempPath,
            filename: fileName,
            caption: `📋 Student IDs for ${uploadedFile.classAssigned} (${students.length} students)`
        });
        
        // Clean up
        if (fs.existsSync(tempPath)) {
            fs.unlinkSync(tempPath);
        }
        
    } catch (error) {
        console.error('Error exporting IDs:', error);
        ctx.reply('❌ An error occurred while exporting student IDs.');
    }
    
    ctx.scene.leave();
});


stage.register(exportIdsScene);

// Edit Student Class Scene 
const editStudentClassScene = new Scenes.BaseScene('edit_student_class_scene');
editStudentClassScene.enter(async (ctx) => {
    try {
        const studentId = ctx.session.editStudentId;
        const student = await getStudentById(studentId);
        
        if (!student) {
            ctx.reply('❌ Student not found.');
            return ctx.scene.leave();
        }
        
        // Get all available classes from uploaded files
        const availableClasses = await getUniqueClasses();
        
        if (availableClasses.length === 0) {
            ctx.reply('❌ No classes found from uploaded lists. Please upload a student list first.');
            return ctx.scene.leave();
        }
        
        // Create inline buttons for each class
        const classButtons = availableClasses.map(className => 
            [Markup.button.callback(
                className, 
                `select_class_${className.replace(/\s+/g, '_')}`
            )]
        );
        
        // Add cancel button
        classButtons.push([Markup.button.callback('❌ Cancel', 'cancel_class_change')]);
        
        ctx.reply(
            `🏫 Select a new class for ${student.name} (Current: ${student.class}):`,
            Markup.inlineKeyboard(classButtons)
        );
    } catch (error) {
        console.error('Error in edit student class scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
        ctx.scene.leave();
    }
});

// Handle class selection
editStudentClassScene.action(/^select_class_(.+)$/, async (ctx) => {
    const className = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();
    
    try {
        const studentId = ctx.session.editStudentId;
        const student = await getStudentById(studentId);
        
        if (!student) {
            ctx.reply('❌ Student not found.');
            return ctx.scene.leave();
        }
        
        const oldClass = student.class;
        student.class = className;
        await student.save();
        
        ctx.reply(`✅ Student ${student.name} moved from "${oldClass}" to "${className}".`, {
            reply_markup: { keyboard: studentManagementMenu.reply_markup.keyboard, resize_keyboard: true }
        });
    } catch (error) {
        console.error('Error changing student class:', error);
        ctx.reply('❌ An error occurred while changing class.');
    }
    
    ctx.scene.leave();
});

// Handle cancel action
editStudentClassScene.action('cancel_class_change', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Class change cancelled.', {
        reply_markup: { keyboard: studentManagementMenu.reply_markup.keyboard, resize_keyboard: true }
    });
    ctx.scene.leave();
});

stage.register(editStudentClassScene);
// Enhanced Edit Student Parent Scene with parent verification
const editStudentParentScene = new Scenes.BaseScene('edit_student_parent_scene');

editStudentParentScene.enter((ctx) => {
    ctx.reply('👨‍👩‍👧‍👦 Please enter the Telegram ID of the new parent.');
});

editStudentParentScene.on('text', async (ctx) => {
    const telegramIdStr = ctx.message.text.trim();
    
    if (!isValidTelegramId(telegramIdStr)) {
        ctx.reply('❌ Invalid Telegram ID. Please provide a valid numeric Telegram ID.');
        return;
    }
    
    const newParentId = telegramIdStr;
    
    try {
        const studentId = ctx.session.editStudentId;
        const student = await getStudentById(studentId);
        
        if (!student) {
            ctx.reply('❌ Student not found.');
            return ctx.scene.leave();
        }
        
        // Find user by Telegram ID
        const newUser = await getUserById(newParentId);
        
        if (!newUser) {
            ctx.reply('❌ User with that Telegram ID not found. They must have interacted with the bot at least once.');
            return ctx.scene.leave();
        }
        
        // Check if the user is already a parent or needs to be converted
        if (newUser.role !== 'parent') {
            // Ask for confirmation to convert user to parent role
            ctx.session.pendingParentId = newParentId;
            ctx.reply(
                `User ${newUser.name} (ID: ${newParentId}) is not currently a parent. ` +
                `Do you want to change their role to parent and link them to this student?`,
                Markup.inlineKeyboard([
                    [Markup.button.callback('✅ Yes', 'confirm_parent_conversion')],
                    [Markup.button.callback('❌ No', 'cancel_parent_change')]
                ])
            );
            return;
        }
        
        // Proceed with linking to existing parent
        await linkStudentToParent(student, newUser);
        
        ctx.reply(`✅ Student ${student.name} is now linked to parent ${newUser.name} (ID: ${newParentId}).`, {
            reply_markup: { keyboard: studentManagementMenu.reply_markup.keyboard, resize_keyboard: true }
        });
        ctx.scene.leave();
        
    } catch (error) {
        console.error('Error changing student parent:', error);
        ctx.reply('❌ An error occurred while changing parent.');
        ctx.scene.leave();
    }
});

// Handle parent conversion confirmation
editStudentParentScene.action('confirm_parent_conversion', async (ctx) => {
    await ctx.answerCbQuery();
    
    try {
        const studentId = ctx.session.editStudentId;
        const newParentId = ctx.session.pendingParentId;
        const student = await getStudentById(studentId);
        const newUser = await getUserById(newParentId);
        
        if (!student || !newUser) {
            ctx.reply('❌ Student or user not found.');
            return ctx.scene.leave();
        }
        
        // Convert user to parent role
        newUser.role = 'parent';
        if (!newUser.studentIds) newUser.studentIds = [];
        await newUser.save();
        
        // Link student to new parent
        await linkStudentToParent(student, newUser);
        
        ctx.reply(`✅ Student ${student.name} is now linked to parent ${newUser.name} (ID: ${newParentId}). ` +
                 `User role has been changed to parent.`, {
            reply_markup: { keyboard: studentManagementMenu.reply_markup.keyboard, resize_keyboard: true }
        });
        
    } catch (error) {
        console.error('Error converting user to parent:', error);
        ctx.reply('❌ An error occurred while converting user to parent.');
    }
    ctx.scene.leave();
});

// Handle parent change cancellation
editStudentParentScene.action('cancel_parent_change', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Parent change cancelled.', {
        reply_markup: { keyboard: studentManagementMenu.reply_markup.keyboard, resize_keyboard: true }
    });
    ctx.scene.leave();
});

// Helper function to link student to parent
const linkStudentToParent = async (student, parent) => {
    // If student already has a parent, remove the link
    if (student.parentId) {
        const oldParent = await getUserById(student.parentId);
        if (oldParent) {
            oldParent.studentIds = oldParent.studentIds.filter(id => id !== student.studentId);
            // If no more students, change role to user
            if (oldParent.studentIds.length === 0) {
                oldParent.role = 'user';
            }
            await oldParent.save();
        }
    }
    
    // Link to new parent
    student.parentId = parent.telegramId;
    await student.save();
    
    // Add student to new parent's list
    if (!parent.studentIds.includes(student.studentId)) {
        parent.studentIds.push(student.studentId);
        await parent.save();
    }
};


stage.register(editStudentParentScene);
// Add Student Scene
const addStudentScene = new Scenes.BaseScene('add_student_scene');
addStudentScene.enter(async (ctx) => {
    ctx.reply('📝 Please provide the student\'s full name.');
});

addStudentScene.on('text', async (ctx) => {
    const studentName = ctx.message.text.trim();
    if (!isValidName(studentName)) {
        ctx.reply('❌ Invalid name. Please provide a non-empty name (max 100 characters).');
        return;
    }
    
    ctx.session.newStudentName = studentName;
    
    // Get all available classes from uploaded files
    const availableClasses = await getUniqueClasses();
    
    if (availableClasses.length === 0) {
        ctx.reply('No classes found. Please upload a student list first or enter the class name manually.');
        ctx.scene.enter('add_student_class_scene');
        return;
    }
    
    // Create inline keyboard with available classes
    const classButtons = availableClasses.map(className => 
        [Markup.button.callback(className, `select_class_${className}`)]
    );
    
    ctx.reply('Please select the class for this student:', Markup.inlineKeyboard(classButtons));
});

// Handle class selection
addStudentScene.action(/^select_class_(.+)$/, async (ctx) => {
    const className = ctx.match[1];
    await ctx.answerCbQuery();
    
    const studentName = ctx.session.newStudentName;
    if (!isValidClassName(className) || !isValidName(studentName)) {
        ctx.reply('❌ Invalid input. Please ensure name and class are valid.');
        ctx.session.newStudentName = null;
        return ctx.scene.leave();
    }
    
    const studentId = await generateUniqueStudentId();
    const newStudent = new Student({
        studentId,
        name: studentName,
        class: className,
        parentId: null,
        grades: {},
        schedule: { monday: 'N/A', tuesday: 'N/A' }
    });
    
    try {
        await newStudent.save();
        ctx.replyWithMarkdown(`✅ Student "${studentName}" added to class "${className}" with unique ID: **${studentId}**
_Share this ID with the parent for registration._`);
    } catch (error) {
        console.error('Error saving student:', error);
        ctx.reply('❌ Failed to add student. Please try again.');
    }
    
    ctx.session.newStudentName = null;
    ctx.scene.leave();
});


stage.register(addStudentScene);

const addStudentClassScene = new Scenes.BaseScene('add_student_class_scene');
addStudentClassScene.enter((ctx) => {
    ctx.reply('Please enter the student\'s class (e.g., Grade 5, Grade 8, Grade 10).');
});

addStudentClassScene.on('text', async (ctx) => {
    const studentClass = ctx.message.text.trim();
    const studentName = ctx.session.newStudentName;
    
    if (!isValidClassName(studentClass) || !isValidName(studentName)) {
        ctx.reply('❌ Invalid input. Please ensure name and class are valid.');
        ctx.session.newStudentName = null;
        return ctx.scene.leave();
    }
    
    const studentId = await generateUniqueStudentId();
    const newStudent = new Student({
        studentId,
        name: studentName,
        class: studentClass,
        parentId: null,
        grades: {},
        schedule: { monday: 'N/A', tuesday: 'N/A' }
    });
    
    try {
        await newStudent.save();
        ctx.replyWithMarkdown(`✅ Student "${studentName}" added to class "${studentClass}" with unique ID: **${studentId}**
_Share this ID with the parent for registration._`);
    } catch (error) {
        console.error('Error saving student:', error);
        ctx.reply('❌ Failed to add student. Please try again.');
    }
    
    ctx.session.newStudentName = null;
    ctx.scene.leave();
});

stage.register(addStudentClassScene);

//
//
//
//uploadStudentListScene
//
//
const uploadStudentListScene = new Scenes.BaseScene('upload_student_list_scene');

uploadStudentListScene.enter((ctx) => {
  ctx.reply('📂 Please upload the student list file (plain text, one name per line).');
});

uploadStudentListScene.on('document', async (ctx) => {
  try {
    const fileId = ctx.message.document.file_id;
    const fileName = ctx.message.document.file_name;
    const fileLink = await ctx.telegram.getFileLink(fileId);

    const https = require('https');
    const fileContent = await new Promise((resolve, reject) => {
      https.get(fileLink.href, (response) => {
        if (response.statusCode !== 200) {
          reject(new Error(`Failed to download file: ${response.statusCode}`));
          return;
        }
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => resolve(data));
      }).on('error', reject);
    });

    const sanitizedFileName = fileName.replace(/[^a-zA-Z0-9._-]/g, '_');
    const tempDir = './temp_uploads';
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
    const tempFilePath = path.join(tempDir, sanitizedFileName);
    fs.writeFileSync(tempFilePath, fileContent);

    const fileIdForStorage = crypto.randomBytes(16).toString('hex');
    ctx.session.tempUploadPath = tempFilePath;
    ctx.session.tempUploadId = fileIdForStorage;

    // ✅ Delay UploadedFile creation until class name is provided
    ctx.session.uploadedFileMeta = {
      id: fileIdForStorage,
      originalName: fileName,
      storedName: sanitizedFileName
    };

    ctx.reply(`✅ File "${fileName}" uploaded. Now, please enter the class name for these students.`);
  } catch (error) {
    console.error('Failed to process student list file:', error);
    ctx.reply('❌ Failed to process the file. Please ensure it is a valid text file.');
    ctx.scene.leave();
  }
});

uploadStudentListScene.on('text', async (ctx) => {
  const className = ctx.message.text.trim();
  if (!isValidClassName(className)) {
    ctx.reply('❌ Invalid class name. Max 50 characters.');
    return;
  }

  const { tempUploadPath, tempUploadId, uploadedFileMeta } = ctx.session;
  if (!tempUploadPath || !tempUploadId || !uploadedFileMeta) {
    ctx.reply('❌ Session error. Please upload again.');
    return ctx.scene.leave();
  }

  try {
    if (!fs.existsSync(tempUploadPath)) {
      ctx.reply('❌ Temporary file not found. Please upload again.');
      return ctx.scene.leave();
    }

    const fileContent = fs.readFileSync(tempUploadPath, 'utf8');
    const studentNames = fileContent.split(/\r?\n/)
      .map(name => name.trim())
      .filter(name => name && isValidName(name));

    if (studentNames.length === 0) {
      ctx.reply('❌ No valid names found in the file.');
      fs.unlinkSync(tempUploadPath);
      delete ctx.session.tempUploadPath;
      delete ctx.session.tempUploadId;
      return ctx.scene.leave();
    }

    let addedCount = 0;
    let errorCount = 0;
    let processedNames = [];

    for (const name of studentNames) {
      try {
        const studentId = await generateUniqueStudentId();
        const newStudent = new Student({
          studentId,
          name,
          class: className,
          parentId: null,
          grades: {},
          schedule: { monday: 'N/A', tuesday: 'N/A' }
        });
        await newStudent.save();
        addedCount++;
        processedNames.push(`${name} (ID: ${studentId})`);
      } catch (error) {
        console.error(`Error adding student ${name}:`, error);
        errorCount++;
      }
    }

    // ✅ Now save UploadedFile with classAssigned
    await new UploadedFile({
      ...uploadedFileMeta,
      uploadDate: new Date(),
      processed: true,
      classAssigned: className
    }).save();

    let summaryMessage = `✅ Successfully added ${addedCount} students to class "${className}".`;
    if (errorCount > 0) summaryMessage += `\n❌ Failed to add ${errorCount} students.`;

    if (addedCount > 10) {
      const summaryContent = `STUDENTS ADDED TO CLASS: ${className}\n\n` +
        processedNames.join('\n') +
        `\n\nTotal: ${addedCount} students\nGenerated on: ${new Date().toLocaleString()}`;
      const summaryFilename = `students_${className.replace(/\s+/g, '_')}_summary.txt`;
      const summaryPath = path.join('./temp_uploads', summaryFilename);
      fs.writeFileSync(summaryPath, summaryContent);
      await ctx.replyWithDocument({ source: summaryPath, filename: summaryFilename });
      fs.unlinkSync(summaryPath);
    } else if (addedCount > 0) {
      summaryMessage += `\n\nAdded students:\n${processedNames.join('\n')}`;
    }

    ctx.reply(summaryMessage);
  } catch (error) {
    console.error('Error adding students:', error);
    ctx.reply('❌ An error occurred while adding students.');
  } finally {
    if (tempUploadPath && fs.existsSync(tempUploadPath)) fs.unlinkSync(tempUploadPath);
    delete ctx.session.tempUploadPath;
    delete ctx.session.tempUploadId;
    delete ctx.session.uploadedFileMeta;
    ctx.scene.leave();
  }
});
stage.register(uploadStudentListScene);

// Register Parent Scene - Fixed to handle adminId constraint
const registerParentScene = new Scenes.BaseScene('register_parent_scene');

registerParentScene.enter((ctx) => {
    const cancelKeyboard = Markup.keyboard([
        ['❌ Cancel']
    ]).resize();

    ctx.reply('👤 To register as a parent, please provide your child\'s Student ID (e.g., ST1234):', cancelKeyboard);
});

registerParentScene.on('text', async (ctx) => {
    const studentId = ctx.message.text.trim();
    
    if (studentId === '❌ Cancel') {
        ctx.reply('❌ Registration cancelled.', parentMenu);
        return ctx.scene.leave();
    }

    if (!isValidStudentId(studentId)) {
        ctx.reply('❌ Invalid Student ID format. Please provide a valid ID (e.g., ST1234).');
        return;
    }
    
    try {
        const student = await getStudentById(studentId);
        
        if (!student) {
            ctx.reply('❌ Student not found. Please check the Student ID and try again.');
            return ctx.scene.leave();
        }

        // Check if student already has a parent or pending parent
        if (student.parentId) {
            ctx.reply('❌ This student is already linked to a parent.');
            return ctx.scene.leave();
        }

        if (student.pendingParentId) {
            ctx.reply('❌ This student already has a pending parent registration.');
            return ctx.scene.leave();
        }

        let parent = await getUserById(ctx.from.id);
        
        // Create or update parent record
        if (!parent) {
            parent = new User({
                telegramId: ctx.from.id,
                username: ctx.from.username || '',
                name: ctx.from.first_name || ctx.from.username || 'Parent',
                role: 'user', // Start as user, will be upgraded to parent after approval
                studentIds: [],
                pendingStudentIds: [studentId],
                adminId: null // Explicitly set adminId to null to avoid duplicate undefined
            });
        } else {
            // Update username and name if available
            if (ctx.from.username && parent.username !== ctx.from.username) {
                parent.username = ctx.from.username;
            }
            if (ctx.from.first_name && parent.name !== ctx.from.first_name) {
                parent.name = ctx.from.first_name;
            }
            
            if (!parent.pendingStudentIds) parent.pendingStudentIds = [];
            if (!parent.pendingStudentIds.includes(studentId)) {
                parent.pendingStudentIds.push(studentId);
            }
            
            // Ensure adminId is set to null if it's undefined
            if (parent.adminId === undefined) {
                parent.adminId = null;
            }
        }

        await parent.save();
        
        // Update student record with pending parent
        student.pendingParentId = ctx.from.id;
        await student.save();
        
        // Notify admins with inline buttons
        const admins = await getAdmins();
        const parentUsername = parent.username ? `@${parent.username}` : 'No username';
        
        for (const admin of admins) {
            try {
                await ctx.telegram.sendMessage(
                    admin.telegramId,
                    `🔔 *New Parent-Student Link Request:*\n\n` +
                    `👤 *Parent:* ${parent.name}\n` +
                    `📱 *Username:* ${parentUsername}\n` +
                    `🆔 *Telegram ID:* ${ctx.from.id}\n\n` +
                    `🎓 *Student:* ${student.name}\n` +
                    `📚 *Student ID:* ${student.studentId}\n` +
                    `🏫 *Class:* ${student.class}\n\n` +
                    `⏰ *Request Time:* ${new Date().toLocaleString()}`,
                    {
                        parse_mode: 'Markdown',
                        ...Markup.inlineKeyboard([
                            [
                                Markup.button.callback('✅ Approve', `approve_parent_${ctx.from.id}_${studentId}`),
                                Markup.button.callback('❌ Deny', `deny_parent_${ctx.from.id}_${studentId}`)
                            ]
                        ])
                    }
                );
            } catch (error) {
                if (error.response?.error_code === 403) {
                    console.log(`Admin ${admin.telegramId} has blocked the bot.`);
                } else {
                    console.error(`Failed to notify admin ${admin.telegramId}:`, error);
                }
            }
        }
        
        ctx.replyWithMarkdown(
            `✅ Your request to link with *${student.name}* has been sent for admin approval.\n\n` +
            `📋 *Details:*\n` +
            `• Student: ${student.name}\n` +
            `• ID: ${student.studentId}\n` +
            `• Class: ${student.class}\n\n` +
            `⏳ Please wait for admin approval. You will be notified once approved.`
        );

    } catch (error) {
        console.error('Error in register parent scene:', error);
        
        // Handle specific MongoDB duplicate key error
        if (error.code === 11000 && error.keyPattern && error.keyPattern.adminId) {
            // Try to fix existing user with undefined adminId
            try {
                await User.updateOne(
                    { telegramId: ctx.from.id, adminId: undefined },
                    { $set: { adminId: null } }
                );
                ctx.reply('⚠️ Please try your registration again.');
            } catch (fixError) {
                ctx.reply('❌ A system error occurred. Please contact an administrator.');
            }
        } else {
            ctx.reply('❌ An error occurred. Please try again.', parentMenu);
        }
    }
    
    ctx.scene.leave();
});

// Handle cancellation
registerParentScene.hears('❌ Cancel', async (ctx) => {
    ctx.reply('❌ Registration cancelled.', parentMenu);
    ctx.scene.leave();
});

// Register the scene
stage.register(registerParentScene);
// Register the scene
stage.register(registerParentScene);

// Link Another Student Scene - Enhanced with username capture
const linkAnotherStudentScene = new Scenes.BaseScene('link_another_student_scene');

linkAnotherStudentScene.enter((ctx) => {
    ctx.reply('🔗 Please provide the student ID of the child you want to link.');
});

linkAnotherStudentScene.on('text', async (ctx) => {
    const studentId = ctx.message.text.trim();
    if (!isValidStudentId(studentId)) {
        ctx.reply('❌ Invalid Student ID. Please provide a 10-digit ID.');
        return ctx.scene.leave();
    }
    
    try {
        const student = await getStudentById(studentId);
        const parent = await getUserById(ctx.from.id);
        
        if (!parent) {
            return ctx.reply('❌ You must be a registered parent to use this feature.');
        }
        if (!student) {
            return ctx.reply('❌ Invalid student ID. Please try again.');
        }
        if (student.parentId || student.pendingParentId) {
            return ctx.reply('❌ This student is already linked or pending approval.');
        }
        if (parent.studentIds.includes(studentId) || (parent.pendingStudentIds && parent.pendingStudentIds.includes(studentId))) {
            return ctx.reply('❌ This student is already linked or pending approval.');
        }
        
        // Update parent username and name if available
        if (ctx.from.username && parent.username !== ctx.from.username) {
            parent.username = ctx.from.username;
        }
        if (ctx.from.first_name && parent.name !== ctx.from.first_name) {
            parent.name = ctx.from.first_name;
        }
        
        if (!parent.pendingStudentIds) parent.pendingStudentIds = [];
        parent.pendingStudentIds.push(studentId);
        await parent.save();
        
        // Update student record
        student.pendingParentId = ctx.from.id;
        await student.save();
        
        // Notify admins
        const admins = await getAdmins();
        for (const admin of admins) {
            try {
                const parentUsername = parent.username ? `@${parent.username}` : 'No username';
                await ctx.telegram.sendMessage(admin.telegramId, 
                    `🔔 *New Parent-Student Link Request:*\n` +
                    `Parent: ${parent.name} (${parentUsername})\n` +
                    `Telegram ID: ${ctx.from.id}\n` +
                    `Student: ${student.name} (ID: ${studentId})`, {
                    parse_mode: 'Markdown',
                    ...Markup.inlineKeyboard([
                        [Markup.button.callback('✅ Approve', `approve_parent_${ctx.from.id}_${studentId}`)],
                        [Markup.button.callback('❌ Deny', `deny_parent_${ctx.from.id}_${studentId}`)]
                    ])
                });
            } catch (error) {
                console.error(`Failed to notify admin ${admin.telegramId}:`, error);
            }
        }
        
        ctx.reply(`✅ Your request to link with ${student.name} has been sent for admin approval.`);
    } catch (error) {
        console.error('Error in link another student scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
    }
    ctx.scene.leave();
});


stage.register(linkAnotherStudentScene);;
//Admin Login Scene - Updated to handle new admin ID format if needed
const adminLoginScene = new Scenes.BaseScene('admin_login_scene');
adminLoginScene.enter((ctx) => ctx.reply('🔑 Please enter the secret admin code.'));
adminLoginScene.on('text', async (ctx) => {
    const code = ctx.message.text.trim();
    if (code === process.env.ADMIN_SECRET_CODE) {
        let admin = await getUserById(ctx.from.id);
        if (!admin) {
            admin = new User({
                telegramId: ctx.from.id,
                role: 'admin',
                name: ctx.from.first_name || 'Admin',
                adminId: await generateUniqueAdminId() // Add admin ID if you want to store it
            });
            await admin.save();
        } else {
            admin.role = 'admin';
            // Add admin ID if not already set
            if (!admin.adminId) {
                admin.adminId = await generateUniqueAdminId();
            }
            await admin.save();
        }
        ctx.reply('✅ Admin login successful!', adminMenu);
    } else {
        ctx.reply('❌ Invalid code. Access denied.');
    }
    ctx.scene.leave();
});
stage.register(adminLoginScene);


// Unbind Parent Scene
const unbindParentScene = new Scenes.BaseScene('unbind_parent_scene');
unbindParentScene.enter((ctx) => ctx.reply('🆔 Please provide the student ID to unbind the parent from.'));
unbindParentScene.on('text', async (ctx) => {
    const studentId = ctx.message.text.trim();
    if (!isValidStudentId(studentId)) {
        ctx.reply('❌ Invalid Student ID. Please provide a 10-digit ID.');
        return;
    }
    try {
        const student = await getStudentById(studentId);
        if (student && student.parentId) {
            const parent = await getUserById(student.parentId);
            if (parent) {
                parent.studentIds = parent.studentIds.filter(id => id !== studentId);
                if (parent.studentIds.length === 0) {
                    parent.role = 'user';
                }
                await parent.save();
            }
            student.parentId = null;
            await student.save();
            ctx.reply(`✅ Parent unbound from student ${student.name} (ID: ${studentId}).`);
        } else {
            ctx.reply('❌ Student ID not found or no parent linked.');
        }
    } catch (error) {
        console.error('Error in unbind parent scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
    }
    ctx.scene.leave();
});
stage.register(unbindParentScene);

//// Edit Student Scene - Updated to show current parent info with Telegram ID
const editStudentScene = new Scenes.BaseScene('edit_student_scene');
editStudentScene.enter((ctx) => ctx.reply('🆔 Please provide the student ID to edit.'));
editStudentScene.on('text', async (ctx) => {
    const studentId = ctx.message.text.trim();
    if (!isValidStudentId(studentId)) {
        ctx.reply('❌ Invalid Student ID. Please provide a 10-digit ID.');
        return ctx.scene.leave();
    }
    try {
        const student = await getStudentById(studentId);
        if (!student) {
            ctx.reply('❌ Student ID not found. Please try again.');
            return ctx.scene.leave();
        }
        
        // Store student info in session
        ctx.session.editStudentId = studentId;
        ctx.session.editStudentName = student.name;
        ctx.session.editStudentClass = student.class;
        ctx.session.editStudentParentId = student.parentId;
        
        // Show student info and edit options
        let parentInfo = 'No parent linked';
        if (student.parentId) {
            const parentUser = await getUserById(student.parentId);
            parentInfo = parentUser ? 
                `${parentUser.name} (ID: ${student.parentId})` : 
                `ID: ${student.parentId}`;
        }
        
        ctx.replyWithMarkdown(
            `📋 *Student Information:*\n` +
            `• Name: ${student.name}\n` +
            `• ID: ${student.studentId}\n` +
            `• Class: ${student.class}\n` +
            `• Parent: ${parentInfo}\n\n` +
            `Which field do you want to edit?`,
            Markup.inlineKeyboard([
                [Markup.button.callback('✏️ Name', 'edit_student_name')],
                [Markup.button.callback('🏫 Class', 'edit_student_class')],
                [Markup.button.callback('👨‍👩‍👧‍👦 Parent', 'edit_student_parent')],
                [Markup.button.callback('⬅️ Cancel', 'cancel_edit_student')]
            ])
        );
    } catch (error) {
        console.error('Error in edit student scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
        ctx.scene.leave();
    }
});
stage.register(editStudentScene); 
const editStudentNameScene = new Scenes.BaseScene('edit_student_name_scene');
editStudentNameScene.enter((ctx) => ctx.reply('Please enter the new name for the student.'));
editStudentNameScene.on('text', async (ctx) => {
    const newName = ctx.message.text.trim();
    if (!isValidName(newName)) {
        ctx.reply('❌ Invalid name. Please provide a non-empty name (max 100 characters).');
        return;
    }
    try {
        const student = await getStudentById(ctx.session.editStudentId);
        if (student && newName) {
            // Clean up any invalid grade entries before saving
            if (student.grades && Array.isArray(student.grades)) {
                student.grades = student.grades.filter(grade => 
                    grade && 
                    grade.score && 
                    grade.purpose && 
                    grade.gradeId && 
                    grade.subject && 
                    grade.teacherId
                );
            }
            
            student.name = newName;
            await student.save();
            ctx.reply(`✅ Student name updated to "${newName}".`);
        } else {
            ctx.reply('❌ Invalid name or student ID.');
        }
    } catch (error) {
        console.error('Error in edit student name scene:', error);
        
        // More specific error handling
        if (error.name === 'ValidationError') {
            ctx.reply('❌ Validation error. The student data contains invalid information. Please contact an administrator.');
        } else {
            ctx.reply('❌ An error occurred. Please try again.');
        }
    }
    ctx.scene.leave();
});
stage.register(editStudentNameScene);


// ===== EDIT TEACHER FUNCTIONALITY =====

// Edit Teacher Scene - Shows list of registered teachers
const editTeacherScene = new Scenes.BaseScene('edit_teacher_scene');

editTeacherScene.enter(async (ctx) => {
    try {
        // Get all registered teachers
        const teachers = await Teacher.find().sort({ name: 1 });
        
        if (teachers.length === 0) {
            ctx.reply('❌ No teachers found. Please add teachers first.');
            return ctx.scene.leave();
        }
        
        // Create inline buttons for each teacher
        const teacherButtons = teachers.map(teacher => 
            [Markup.button.callback(
                `${teacher.name} (ID: ${teacher.teacherId})`, 
                `select_teacher_${teacher.teacherId}`
            )]
        );
        
        // Add cancel button
        teacherButtons.push([Markup.button.callback('❌ Cancel', 'cancel_edit_teacher')]);
        
        ctx.reply('🧑🏫 Select a teacher to edit:', Markup.inlineKeyboard(teacherButtons));
    } catch (error) {
        console.error('Error retrieving teachers:', error);
        ctx.reply('❌ An error occurred while retrieving teachers.');
        ctx.scene.leave();
    }
});

// Handle teacher selection
editTeacherScene.action(/^select_teacher_(.+)$/, async (ctx) => {
    const teacherId = ctx.match[1];
    await ctx.answerCbQuery();
    
    try {
        const teacher = await getTeacherById(teacherId);
        if (!teacher) {
            ctx.reply('❌ Teacher not found. Please try again.');
            return ctx.scene.leave();
        }
        
        // Store teacher info in session
        ctx.session.editTeacherId = teacherId;
        ctx.session.editTeacherName = teacher.name;
        
// In the editTeacherScene.action(/^select_teacher_(.+)$/ handler, update the message:
let subjectsInfo = teacher.subjects.length > 0 ? 
    teacher.subjects.join(', ') : 
    'No subjects assigned';

// Add telegramInfo definition
let telegramInfo = teacher.telegramId ? 
    `${teacher.telegramId}` : 
    'Not linked';

ctx.replyWithMarkdown(
    `📋 *Teacher Information:*\n` +
    `• Name: ${teacher.name}\n` +
    `• ID: ${teacher.teacherId}\n` +
    `• Telegram ID: ${telegramInfo}\n` +
    `• Subjects: ${subjectsInfo}\n\n` +
    `Which field do you want to edit?`,
    Markup.inlineKeyboard([
        [Markup.button.callback('✏️ Name', 'edit_teacher_name')],
        [Markup.button.callback('📚 Manage Subjects', 'edit_teacher_subjects')],
        [Markup.button.callback('🔗 Telegram ID', 'edit_teacher_telegram')],
        [Markup.button.callback('⬅️ Cancel', 'cancel_edit_teacher')]
    ])
);
    } catch (error) {
        console.error('Error in edit teacher scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
        ctx.scene.leave();
    }
});

// Handle cancel action
editTeacherScene.action('cancel_edit_teacher', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('❌ Edit cancelled.', {
        reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
    });
    ctx.scene.leave();
});


// Edit Teacher Name Scene
const editTeacherNameScene = new Scenes.BaseScene('edit_teacher_name_scene');
editTeacherNameScene.enter((ctx) => ctx.reply('Please enter the new name for the teacher.'));
editTeacherNameScene.on('text', async (ctx) => {
    const newName = ctx.message.text.trim();
    if (!isValidName(newName)) {
        ctx.reply('❌ Invalid name. Please provide a non-empty name (max 100 characters).');
        return;
    }
    try {
        const teacher = await getTeacherById(ctx.session.editTeacherId);
        if (teacher && newName) {
            teacher.name = newName;
            await teacher.save();
            const user = await getUserById(teacher.telegramId);
            if (user) {
                user.name = newName;
                await user.save();
            }
            ctx.reply(`✅ Teacher name updated to "${newName}".`);
        } else {
            ctx.reply('❌ Invalid name or teacher ID.');
        }
    } catch (error) {
        console.error('Error in edit teacher name scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
    }
    ctx.scene.leave();
});

// Enhanced Edit Teacher Subjects Scene with Remove: Subject format
const editTeacherSubjectsScene = new Scenes.BaseScene('edit_teacher_subjects_scene');

editTeacherSubjectsScene.enter(async (ctx) => {
    try {
        const teacherId = ctx.session.editTeacherId;
        const teacher = await getTeacherById(teacherId);
        
        if (!teacher) {
            ctx.reply('❌ Teacher not found.', {
                reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
            });
            return ctx.scene.leave();
        }
        
        const subjects = teacher.subjects || [];
        
        if (subjects.length === 0) {
            ctx.reply('📚 This teacher has no subjects assigned yet.', Markup.inlineKeyboard([
                [Markup.button.callback('➕ Add Subject', 'add_new_subject_to_teacher')],
                [Markup.button.callback('⬅️ Back to Teacher Edit', 'back_to_teacher_edit')]
            ]));
            return;
        }
        
        let message = `📚 *Current Subjects for ${teacher.name}:*\n\n`;
        
        subjects.forEach((subject, index) => {
            message += `${index + 1}. ${subject}\n`;
        });
        
        // Create inline buttons with "Remove: Subject" format
        const subjectButtons = subjects.map(subject => 
            [Markup.button.callback(`🗑️ Remove: ${subject}`, `remove_subject_${subject.replace(/ /g, '_')}`)]
        );
        
        // Add add button and back button
        subjectButtons.push(
            [Markup.button.callback('➕ Add Subject', 'add_new_subject_to_teacher')],
            [Markup.button.callback('⬅️ Back to Teacher Edit', 'back_to_teacher_edit')]
        );
        
        ctx.replyWithMarkdown(message, Markup.inlineKeyboard(subjectButtons));
        
    } catch (error) {
        console.error('Error in edit teacher subjects scene:', error);
        ctx.reply('❌ An error occurred while retrieving subjects.', {
            reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
        });
        ctx.scene.leave();
    }
});

// Handle subject removal
editTeacherSubjectsScene.action(/^remove_subject_(.+)$/, async (ctx) => {
    const subjectToRemove = ctx.match[1].replace(/_/g, ' ');
    await ctx.answerCbQuery();
    
    try {
        const teacherId = ctx.session.editTeacherId;
        const teacher = await getTeacherById(teacherId);
        
        if (!teacher) {
            ctx.reply('❌ Teacher not found.');
            return ctx.scene.leave();
        }
        
        // Remove the subject
        teacher.subjects = teacher.subjects.filter(s => s !== subjectToRemove);
        await teacher.save();
        
        // Update user record if it exists
        if (teacher.telegramId) {
            const user = await getUserById(teacher.telegramId);
            if (user) {
                user.subjects = user.subjects.filter(s => s !== subjectToRemove);
                await user.save();
            }
        }
        
        ctx.reply(`✅ Subject "${subjectToRemove}" has been removed from ${teacher.name}.`);
        
        // Refresh the subject list
        setTimeout(() => {
            ctx.scene.reenter();
        }, 1000);
        
    } catch (error) {
        console.error('Error removing subject:', error);
        ctx.reply('❌ An error occurred while removing the subject.');
        ctx.scene.leave();
    }
});

// Handle add new subject
editTeacherSubjectsScene.action('add_new_subject_to_teacher', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('📝 Please enter the new subject to add:');
    ctx.scene.enter('add_subject_to_teacher_scene');
});

// Handle back to teacher edit
editTeacherSubjectsScene.action('back_to_teacher_edit', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('edit_teacher_scene');
});

// Add menu return handler
editTeacherSubjectsScene.hears(['⬅️ Main Menu', '🏠 Main Menu', '↩️ Main Menu', '🔙 Main Menu'], async (ctx) => {
    await returnToM
});

// Add Subject to Teacher Scene
const addSubjectToTeacherScene = new Scenes.BaseScene('add_subject_to_teacher_scene');

addSubjectToTeacherScene.enter((ctx) => {
    ctx.reply('📝 Please enter the new subject to add to this teacher:');
});

addSubjectToTeacherScene.on('text', async (ctx) => {
    const newSubject = ctx.message.text.trim();
    
    if (!isValidSubject(newSubject)) {
        ctx.reply('❌ Invalid subject. Please enter a non-empty subject name (max 50 characters).');
        return;
    }
    
    try {
        const teacherId = ctx.session.editTeacherId;
        const teacher = await getTeacherById(teacherId);
        
        if (!teacher) {
            ctx.reply('❌ Teacher not found.', {
                reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
            });
            return ctx.scene.leave();
        }
        
        // Check if subject already exists
        if (teacher.subjects.includes(newSubject)) {
            ctx.reply(`❌ Subject "${newSubject}" is already assigned to this teacher.`);
            return ctx.scene.leave();
        }
        
        // Add the subject
        teacher.subjects.push(newSubject);
        await teacher.save();
        
        // Update user record if it exists
        if (teacher.telegramId) {
            const user = await getUserById(teacher.telegramId);
            if (user) {
                if (!user.subjects.includes(newSubject)) {
                    user.subjects.push(newSubject);
                    await user.save();
                }
            }
        }
        
        ctx.reply(`✅ Subject "${newSubject}" has been added to ${teacher.name}.`);
        
        // Return to subjects management
        setTimeout(() => {
            ctx.scene.enter('edit_teacher_subjects_scene');
        }, 1000);
        
    } catch (error) {
        console.error('Error adding subject to teacher:', error);
        ctx.reply('❌ An error occurred while adding the subject.', {
            reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
        });
        ctx.scene.leave();
    }
});

// Handle back to subjects
addSubjectToTeacherScene.action('back_to_subjects', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('edit_teacher_subjects_scene');
});

addSubjectToTeacherScene.hears(['⬅️ Back', '🔙 Back'], async (ctx) => {
    ctx.scene.enter('edit_teacher_subjects_scene');
});

// Add menu return handler
addSubjectToTeacherScene.hears(['⬅️ Main Menu', '🏠 Main Menu', '↩️ Main Menu', '🔙 Main Menu'], async (ctx) => {
    await returnToMenu(ctx, '❌ Subject addition cancelled.');
});
stage.register(addSubjectToTeacherScene);

// Edit Teacher Telegram ID Scene
const editTeacherTelegramScene = new Scenes.BaseScene('edit_teacher_telegram_scene');
editTeacherTelegramScene.enter((ctx) => {
    ctx.reply('📱 Please enter the new Telegram ID for the teacher.');
});
editTeacherTelegramScene.on('text', async (ctx) => {
    const newTelegramId = ctx.message.text.trim();
    
    if (!isValidTelegramId(newTelegramId)) {
        ctx.reply('❌ Invalid Telegram ID. Please provide a valid numeric Telegram ID.');
        return;
    }
    
    try {
        const teacherId = ctx.session.editTeacherId;
        const teacher = await getTeacherById(teacherId);
        
        if (!teacher) {
            ctx.reply('❌ Teacher not found.');
            return ctx.scene.leave();
        }
        
        // Check if Telegram ID is already linked to another teacher
        const existingTeacher = await Teacher.findOne({ telegramId: newTelegramId });
        if (existingTeacher && existingTeacher.teacherId !== teacherId) {
            ctx.reply(`❌ This Telegram ID is already linked to teacher ${existingTeacher.name}.`);
            return ctx.scene.leave();
        }
        
        // Update teacher record
        const oldTelegramId = teacher.telegramId;
        teacher.telegramId = newTelegramId;
        await teacher.save();
        
        // Update user record if it exists
        if (oldTelegramId) {
            const oldUser = await getUserById(oldTelegramId);
            if (oldUser) {
                oldUser.role = 'user'; // Demote to user role
                await oldUser.save();
            }
        }
        
        // Create or update user record for new Telegram ID
        let newUser = await getUserById(newTelegramId);
        if (!newUser) {
            newUser = new User({
                telegramId: newTelegramId,
                name: teacher.name,
                role: 'teacher',
                subjects: teacher.subjects
            });
        } else {
            newUser.role = 'teacher';
            newUser.name = teacher.name;
            newUser.subjects = teacher.subjects;
        }
        await newUser.save();
        
        ctx.reply(`✅ Teacher Telegram ID updated to ${newTelegramId}.`, {
            reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
        });
        
    } catch (error) {
        console.error('Error updating teacher Telegram ID:', error);
        ctx.reply('❌ An error occurred while updating Telegram ID.');
    }
    
    ctx.scene.leave();
});


// ===== REGISTER ALL TEACHER SCENES =====
stage.register(editTeacherScene);
stage.register(editTeacherNameScene);
stage.register(editTeacherSubjectsScene);
stage.register(editTeacherTelegramScene);

// Announcement Recipient Scene - Updated with All Admins option
const announcementRecipientScene = new Scenes.BaseScene('announcement_recipient_scene');
announcementRecipientScene.enter((ctx) => {
    ctx.reply('📢 Who do you want to send the announcement to?', Markup.inlineKeyboard([
        [Markup.button.callback('👑 All Admins', 'announce_admins')],
        [Markup.button.callback('👨‍👩‍👧‍👦 All Parents', 'announce_parents')],
        [Markup.button.callback('🧑🏫 All Teachers', 'announce_teachers')],
        [Markup.button.callback('❌ Cancel', 'cancel_announcement')]
    ]));
});

announcementRecipientScene.action('announce_admins', async (ctx) => {
    ctx.session.announcementTarget = 'admins';
    await ctx.answerCbQuery();
    await ctx.reply('📝 Please send the announcement message or media to send to all admins.');
    ctx.scene.enter('send_announcement_scene');
});

announcementRecipientScene.action('announce_parents', async (ctx) => {
    ctx.session.announcementTarget = 'parents';
    await ctx.answerCbQuery();
    await ctx.reply('📝 Please send the announcement message to send to all parents.');
    ctx.scene.enter('send_announcement_scene');
});

announcementRecipientScene.action('announce_teachers', async (ctx) => {
    ctx.session.announcementTarget = 'teachers';
    await ctx.answerCbQuery();
    await ctx.reply('📝 Please send the announcement message to send to all teachers.');
    ctx.scene.enter('send_announcement_scene');
});

announcementRecipientScene.action('cancel_announcement', async (ctx) => {
    await ctx.answerCbQuery();
    await ctx.reply('❌ Announcement cancelled.', adminMenu);
    ctx.scene.leave();
});
stage.register(announcementRecipientScene);
//sendAnnouncementScene
const sendAnnouncementScene = new Scenes.BaseScene('send_announcement_scene');

sendAnnouncementScene.enter(async (ctx) => {
  ctx.reply('📝 Please send the announcement message or media you want to send.');
});

sendAnnouncementScene.on(['text', 'photo', 'video', 'document', 'audio', 'voice'], async (ctx) => {
  // Extract announcement text or caption
  const isText = ctx.message.text || false;
  const isMedia =
    ctx.message.photo || ctx.message.video || ctx.message.document || ctx.message.audio || ctx.message.voice;

  let announcementText = '';
  if (isText) {
    announcementText = ctx.message.text.trim();
    if (!announcementText) {
      ctx.reply('❌ Announcement cannot be empty. Please send the announcement message or media again.');
      return;
    }
  } else if (isMedia) {
    // Use caption if available or empty string
    announcementText = ctx.message.caption ? ctx.message.caption.trim() : '';
  }

  const target = ctx.session.announcementTarget;
  if (!target) {
    ctx.reply('❌ Target audience not set. Please start again.');
    return ctx.scene.leave();
  }

  // Get sender's Telegram name for display
  const senderName = ctx.from.first_name || ctx.from.username || 'Admin';

  try {
    // Determine recipients by role
    let recipients;
    if (target === 'admins') {
      recipients = await User.find({ role: 'admin' });
    } else if (target === 'parents') {
      recipients = await User.find({ role: 'parent' });
    } else if (target === 'teachers') {
      recipients = await User.find({ role: 'teacher' });
    } else {
      ctx.reply('❌ Invalid target audience.');
      return ctx.scene.leave();
    }

    // Filter out the sender from recipients to avoid sending to themselves
    const filteredRecipients = recipients.filter(recipient => recipient.telegramId !== ctx.from.id.toString());

    let successCount = 0;
    let failedCount = 0;

    for (const user of filteredRecipients) {
      try {
        // Send appropriate message based on content type
        if (isText) {
          // Send text announcement
          await ctx.telegram.sendMessage(
            user.telegramId,
            `📢 *Announcement from ${senderName}:*\n${announcementText}`,
            { parse_mode: 'Markdown' }
          );
          successCount++;
        } else if (isMedia) {
          // Send media with optional caption prepended with announcement header
          const caption = announcementText
            ? `📢 *Announcement from ${senderName}:*\n${announcementText}`
            : `📢 Announcement from ${senderName}`;

          if (ctx.message.photo) {
            // Photo array, send highest resolution photo
            const photoArray = ctx.message.photo;
            const highestResPhoto = photoArray[photoArray.length - 1];
            await ctx.telegram.sendPhoto(user.telegramId, highestResPhoto.file_id, {
              caption,
              parse_mode: 'Markdown'
            });
            successCount++;
          } else if (ctx.message.video) {
            await ctx.telegram.sendVideo(user.telegramId, ctx.message.video.file_id, {
              caption,
              parse_mode: 'Markdown'
            });
            successCount++;
          } else if (ctx.message.document) {
            await ctx.telegram.sendDocument(user.telegramId, ctx.message.document.file_id, {
              caption,
              parse_mode: 'Markdown'
            });
            successCount++;
          } else if (ctx.message.audio) {
            await ctx.telegram.sendAudio(user.telegramId, ctx.message.audio.file_id, {
              caption,
              parse_mode: 'Markdown'
            });
            successCount++;
          } else if (ctx.message.voice) {
            await ctx.telegram.sendVoice(user.telegramId, ctx.message.voice.file_id, {
              caption,
              parse_mode: 'Markdown'
            });
            successCount++;
          }
        }
      } catch (error) {
        if (error.response && error.response.error_code === 403) {
          console.log(`User ${user.telegramId} has blocked the bot.`);
          failedCount++;
        } else {
          console.error(`Failed to send announcement to ${user.telegramId}:`, error);
          failedCount++;
        }
      }
    }

    // Send summary to the sender
    let summaryMessage = `✅ Announcement sent successfully!\n\n`;
    summaryMessage += `• Target: ${target}\n`;
    summaryMessage += `• Successful deliveries: ${successCount}\n`;
    summaryMessage += `• Failed deliveries: ${failedCount}\n`;
    
    if (filteredRecipients.length === 0) {
      summaryMessage = `ℹ️ No recipients found for ${target} (excluding yourself).`;
    }

    ctx.reply(summaryMessage, adminMenu);

  } catch (error) {
    console.error('Error in send announcement scene:', error);
    ctx.reply('❌ An error occurred. Please try again.', adminMenu);
  } finally {
    ctx.scene.leave();
  }
});

// Handle unsupported media types
sendAnnouncementScene.on('message', (ctx) => {
  ctx.reply('❌ Unsupported message type. Please send text, photo, video, document, audio, or voice.');
});

stage.register(sendAnnouncementScene);

// Teacher Subject Registration Scene
const registerTeacherSubjectScene = new Scenes.BaseScene('register_teacher_subject_scene');
registerTeacherSubjectScene.enter((ctx) =>
    ctx.reply('🧑🏫 Please enter the subject you teach (e.g., Math, Science).')
);
registerTeacherSubjectScene.on('text', async (ctx) => {
    const subject = ctx.message.text.trim();
    if (!isValidSubject(subject)) {
        ctx.reply('❌ Invalid subject. Please enter a non-empty subject name (max 50 characters).');
        return;
    }
    try {
        const user = await getUserById(ctx.from.id);
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (user && teacher) {
            if (teacher.pendingSubjects && teacher.pendingSubjects.includes(subject)) {
                ctx.reply(`❌ "${subject}" is already pending verification.`);
                return ctx.scene.leave();
            }
            
            if (!teacher.pendingSubjects) teacher.pendingSubjects = [];
            teacher.pendingSubjects.push(subject);
            await teacher.save();
            
            const admins = await getAdmins();
            for (const admin of admins) {
                try {
                    ctx.telegram.sendMessage(admin.telegramId, `🔔 *New Subject Verification Request from ${teacher.name}:*
Subject: **${subject}**
Teacher ID: **${teacher.teacherId}**`, {
                        parse_mode: 'Markdown',
                        ...Markup.inlineKeyboard([
                            [Markup.button.callback('✅ Approve', `approve_subject_${teacher.teacherId}_${subject.replace(/ /g, '_')}`)],
                            [Markup.button.callback('❌ Deny', `deny_subject_${teacher.teacherId}_${subject.replace(/ /g, '_')}`)]
                        ])
                    });
                } catch (error) {
                    console.error(`Failed to notify admin ${admin.telegramId}:`, error);
                }
            }
            ctx.reply(`✅ Your request to add "${subject}" has been sent for admin verification.`, teacherMenu);
        } else {
            ctx.reply('❌ An error occurred. Please contact an admin.');
        }
    } catch (error) {
        console.error('Error in register teacher subject scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
    }
    ctx.scene.leave();
});
stage.register(registerTeacherSubjectScene);

;

/// Search Admin Scene for Admins - Updated with category selection
const searchAdminScene = new Scenes.BaseScene('search_admin_scene');

searchAdminScene.enter((ctx) => {
    ctx.reply('🔍 What would you like to search for?', Markup.inlineKeyboard([
        [Markup.button.callback('👥 Staff (Admins & Teachers)', 'search_staff')],
        [Markup.button.callback('👨‍👩‍👧‍👦 Parents', 'search_parents')],
        [Markup.button.callback('🎓 Students', 'search_students')],
        [Markup.button.callback('❌ Cancel', 'cancel_search')]
    ]));
});

// Handle category selection
searchAdminScene.action('search_staff', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.session.searchCategory = 'staff';
    ctx.reply('🔍 Please enter the name or ID to search for staff (admins & teachers):\n\nType "❌ Cancel" at any time to return to the main menu.', Markup.keyboard([['❌ Cancel']]).resize());
});

searchAdminScene.action('search_parents', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.session.searchCategory = 'parents';
    ctx.reply('🔍 Please enter the name or ID to search for parents:\n\nType "❌ Cancel" at any time to return to the main menu.', Markup.keyboard([['❌ Cancel']]).resize());
});

searchAdminScene.action('search_students', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.session.searchCategory = 'students';
    ctx.reply('🔍 Please enter the name or ID to search for students:\n\nType "❌ Cancel" at any time to return to the main menu.', Markup.keyboard([['❌ Cancel']]).resize());
});

// Handle cancel action from inline keyboard
searchAdminScene.action('cancel_search', async (ctx) => {
    await ctx.answerCbQuery();
    await returnToAdminMenu(ctx, '❌ Search cancelled.');
});

// Handle cancel from text input
searchAdminScene.hears('❌ Cancel', async (ctx) => {
    await returnToAdminMenu(ctx, '❌ Search cancelled.');
});

// Handle search query
searchAdminScene.on('text', async (ctx) => {
    const query = ctx.message.text.trim();
    
    // Check for cancel command
    if (query === '❌ Cancel') {
        await returnToAdminMenu(ctx, '❌ Search cancelled.');
        return;
    }
    
    const category = ctx.session.searchCategory;
    const searchQuery = query.toLowerCase();
    
    if (!searchQuery) {
        ctx.reply('❌ Search query cannot be empty.');
        return;
    }
    
    if (!category) {
        ctx.reply('❌ Please select a search category first.');
        return ctx.scene.reenter();
    }
    
    try {
        let results = '';
        let inlineKeyboard = [];
        
        if (category === 'staff') {
            // Search admins
            const adminResults = await User.find({
                role: 'admin',
                $or: [
                    { name: { $regex: searchQuery, $options: 'i' } },
                    { telegramId: { $regex: searchQuery } }
                ]
            });
            
            // Search teachers
            const teacherResults = await Teacher.find({
                $or: [
                    { name: { $regex: searchQuery, $options: 'i' } },
                    { teacherId: { $regex: searchQuery } },
                    { telegramId: { $regex: searchQuery } }
                ]
            });
            
            if (adminResults.length > 0) {
                results += '👑 *Found Admins:*\n';
                adminResults.forEach(admin => {
                    results += `• Name: ${admin.name}, Telegram ID: ${admin.telegramId}\n`;
                });
                results += '\n';
            }
            
            if (teacherResults.length > 0) {
                results += '🧑🏫 *Found Teachers:*\n';
                teacherResults.forEach(teacher => {
                    const subjects = teacher.subjects.length > 0 ? teacher.subjects.join(', ') : 'N/A';
                    const telegramInfo = teacher.telegramId ? `, Telegram ID: ${teacher.telegramId}` : '';
                    results += `• Name: ${teacher.name}, ID: ${teacher.teacherId}${telegramInfo}, Subjects: ${subjects}\n`;
                });
            }
            
            if (adminResults.length === 0 && teacherResults.length === 0) {
                results = '❌ No staff members found matching your search.';
            }
            
        } else if (category === 'parents') {
            const parentResults = await User.find({
                role: 'parent',
                $or: [
                    { name: { $regex: searchQuery, $options: 'i' } },
                    { telegramId: { $regex: searchQuery } }
                ]
            });
            
            if (parentResults.length > 0) {
                results += '👨‍👩‍👧‍👦 *Found Parents:*\n';
                
                // Get detailed information for each parent
                const detailedParents = await Promise.all(
                    parentResults.map(async (parent) => {
                        const students = await getStudentsByParentId(parent.telegramId);
                        const studentCount = students.length;
                        return { parent, studentCount };
                    })
                );
                
                detailedParents.forEach(({ parent, studentCount }) => {
                    results += `• Name: ${parent.name}, Telegram ID: ${parent.telegramId}, Linked Students: ${studentCount}\n`;
                });
            } else {
                results = '❌ No parents found matching your search.';
            }
            
        } else if (category === 'students') {
            const studentResults = await Student.find({
                $or: [
                    { name: { $regex: searchQuery, $options: 'i' } },
                    { studentId: { $regex: searchQuery } },
                    { class: { $regex: searchQuery, $options: 'i' } }
                ]
            }).sort({ name: 1 });
            
            if (studentResults.length > 0) {
                results += '🎓 *Found Students:*\n';
                
                // Get parent information for each student
                const detailedStudents = await Promise.all(
                    studentResults.map(async (student) => {
                        let parentInfo = 'No parent linked';
                        if (student.parentId) {
                            const parent = await getUserById(student.parentId);
                            parentInfo = parent ? parent.name : `ID: ${student.parentId}`;
                        }
                        return { student, parentInfo };
                    })
                );
                
                detailedStudents.forEach(({ student, parentInfo }) => {
                    results += `• Name: ${student.name}, ID: ${student.studentId}, Class: ${student.class}, Parent: ${parentInfo}\n`;
                    inlineKeyboard.push([Markup.button.callback(`💯 Manage ${student.name}'s Grades`, `manage_grades_${student.studentId}`)]);
                });
            } else {
                results = '❌ No students found matching your search.';
            }
        }
        
        if (results) {
            // Add continue searching option
            if (inlineKeyboard.length === 0) {
                inlineKeyboard.push([Markup.button.callback('🔍 Search Again', 'search_again')]);
            }
            inlineKeyboard.push([Markup.button.callback('🏠 Main Menu', 'return_to_menu')]);
            
            ctx.replyWithMarkdown(results, { 
                reply_markup: Markup.inlineKeyboard(inlineKeyboard) 
            });
        }
        
    } catch (error) {
        console.error('Error in search admin scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
    }
    
    // Clear search session
    delete ctx.session.searchCategory;
});

// Handle search again action
searchAdminScene.action('search_again', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.reenter();
});

// Handle return to menu action
searchAdminScene.action('return_to_menu', async (ctx) => {
    await ctx.answerCbQuery();
    await returnToAdminMenu(ctx, 'Returning to main menu.');
});

// Helper function to return to admin menu
const returnToAdminMenu = async (ctx, message = 'Returning to main menu.') => {
    // Clear session data
    if (ctx.session) {
        delete ctx.session.searchCategory;
    }
    
    // Leave scene and return to admin menu
    if (ctx.scene) {
        await ctx.scene.leave();
    }
    await ctx.reply(message, adminMenu);
};

stage.register(searchAdminScene);

// Contact Parent Scene
const contactParentScene = new Scenes.BaseScene('contact_parent_scene');
contactParentScene.enter((ctx) => ctx.reply('🆔 Please enter the student ID of the parent you want to contact.'));
contactParentScene.on('text', async (ctx) => {
    const studentId = ctx.message.text.trim();
    if (!isValidStudentId(studentId)) {
        ctx.reply('❌ Invalid Student ID. Please provide a 10-digit ID.');
        return ctx.scene.leave();
    }
    try {
        const student = await getStudentById(studentId);
        if (!student || !student.parentId) {
            return ctx.reply('❌ Student ID not found or student has no linked parent.');
        }
        ctx.session.recipientId = student.parentId;
        ctx.reply('📝 Please type the message you want to send to the parent.');
        ctx.scene.enter('send_message_scene');
    } catch (error) {
        console.error('Error in contact parent scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
        ctx.scene.leave();
    }
});
stage.register(contactParentScene);

const sendMessageScene = new Scenes.BaseScene('send_message_scene');
sendMessageScene.on('text', async (ctx) => {
    const message = ctx.message.text.trim();
    const recipientId = ctx.session.recipientId;
    if (!isValidAnnouncementOrMessage(message) || !recipientId) {
        ctx.reply('❌ Message cannot be empty or recipient not set.');
        return ctx.scene.leave();
    }
    try {
        const sender = await getUserById(ctx.from.id);
        const senderRole = sender.role === 'teacher' ? 'Teacher' : 'Admin';
        await ctx.telegram.sendMessage(recipientId, `📢 *Message from ${senderRole} (${sender.name}):*
${message}`, { parse_mode: 'Markdown' });
        ctx.reply('✅ Message sent successfully.', teacherMenu);
    } catch (error) {
        if (error.response && error.response.error_code === 403) {
            ctx.reply('❌ Failed to send message. The recipient has blocked the bot.');
        } else {
            console.error(`Failed to send message:`, error);
            ctx.reply('❌ Failed to send message. Please try again later.');
        }
    } finally {
        ctx.session.recipientId = null;
        ctx.scene.leave();
    }
});
stage.register(sendMessageScene);

// Contact Admin Scene for Parents
const contactAdminScene = new Scenes.BaseScene('contact_admin_scene');
contactAdminScene.enter((ctx) => ctx.reply('📝 Please type the message you want to send to the administrators.'));
contactAdminScene.on('text', async (ctx) => {
    const message = ctx.message.text.trim();
    if (!isValidAnnouncementOrMessage(message)) {
        ctx.reply('❌ Message cannot be empty.');
        return;
    }
    try {
        const admins = await getAdmins();
        const senderName = ctx.from.first_name || 'Parent';
        if (admins.length > 0) {
            for (const admin of admins) {
                try {
                    await ctx.telegram.sendMessage(admin.telegramId, `📢 *New message from a parent (${senderName}):*
${message}`, { parse_mode: 'Markdown' });
                } catch (error) {
                    if (error.response && error.response.error_code === 403) {
                        console.log(`Admin ${admin.telegramId} has blocked the bot.`);
                    } else {
                        console.error(`Failed to send message to admin ${admin.telegramId}:`, error);
                    }
                }
            }
            ctx.reply('✅ Your message has been sent to the administrators.', parentMenu);
        } else {
            ctx.reply('❌ No administrators found to send the message to.');
        }
    } catch (error) {
        console.error('Error in contact admin scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
    }
    ctx.scene.leave();
});
stage.register(contactAdminScene);

// Add Teacher Scene - Fixed for sparse index
const addTeacherScene = new Scenes.BaseScene('add_teacher_scene');
addTeacherScene.enter((ctx) => ctx.reply('📝 Please provide the teacher\'s full name.'));
addTeacherScene.on('text', async (ctx) => {
    const teacherName = ctx.message.text.trim();
    if (!isValidName(teacherName)) {
        ctx.reply('❌ Invalid name. Please provide a non-empty name (max 100 characters).');
        return;
    }
    try {
        const teacherId = await generateUniqueTeacherId();
        
        // Create teacher without telegramId field (not undefined or null)
        const newTeacher = new Teacher({
            teacherId,
            name: teacherName,
            // Do NOT include telegramId field for new teachers
            subjects: [],
            pendingSubjects: []
        });
        
        await newTeacher.save();
        
        ctx.replyWithMarkdown(`✅ Teacher "${teacherName}" added with unique ID: **${teacherId}**
_Share this ID with the teacher for registration._`);
        
    } catch (error) {
        console.error('Error in add teacher scene:', error);
        
        // Handle duplicate key error for telegramId
        if (error.code === 11000 && error.keyPattern && error.keyPattern.telegramId) {
            // Clean up existing null telegramId values
            try {
                await Teacher.updateMany(
                    { telegramId: null },
                    { $unset: { telegramId: 1 } }
                );
                ctx.reply('⚠️ Please try adding the teacher again.');
            } catch (fixError) {
                ctx.reply('❌ A system error occurred. Please contact an administrator.');
            }
        } else {
            ctx.reply('❌ An error occurred. Please try again.');
        }
    }
    
    ctx.scene.leave();
});

addTeacherScene.leave((ctx) => ctx.reply('⬅️ Returning to user management menu.', {
    reply_markup: { keyboard: userManagementMenu.reply_markup.keyboard, resize_keyboard: true }
}));
stage.register(addTeacherScene);
// Add Subject Scene
const addSubjectScene = new Scenes.BaseScene('add_subject_scene');
addSubjectScene.enter((ctx) => ctx.reply('📚 Please enter the new subject you want to add. An admin will review your request.'));
addSubjectScene.on('text', async (ctx) => {
    const newSubject = ctx.message.text.trim();
    if (!isValidSubject(newSubject)) {
        ctx.reply('❌ Invalid subject. Please enter a non-empty subject name (max 50 characters).');
        return;
    }
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (!teacher) {
            return ctx.reply('❌ An error occurred. Please contact an admin.');
        }
        const subjects = teacher.subjects || [];
        const pendingSubjects = teacher.pendingSubjects || [];
        
        if (subjects.includes(newSubject) || pendingSubjects.includes(newSubject)) {
            return ctx.reply(`❌ "${newSubject}" is already one of your subjects or is pending verification.`);
        }
        
        if (!teacher.pendingSubjects) teacher.pendingSubjects = [];
        teacher.pendingSubjects.push(newSubject);
        await teacher.save();
        
        const admins = await getAdmins();
        for (const admin of admins) {
            try {
                await ctx.telegram.sendMessage(admin.telegramId, `🔔 *New Subject Verification Request from ${teacher.name}:*
Subject: **${newSubject}**
Teacher ID: **${teacher.teacherId}**`, {
                    parse_mode: 'Markdown',
                    ...Markup.inlineKeyboard([
                        [Markup.button.callback('✅ Approve', `approve_subject_${teacher.teacherId}_${newSubject.replace(/ /g, '_')}`)],
                        [Markup.button.callback('❌ Deny', `deny_subject_${teacher.teacherId}_${newSubject.replace(/ /g, '_')}`)]
                    ])
                });
            } catch (error) {
                if (error.response && error.response.error_code === 403) {
                    console.log(`Admin ${admin.telegramId} has blocked the bot.`);
                } else {
                    console.error(`Failed to notify admin ${admin.telegramId}:`, error);
                }
            }
        }
        ctx.reply(`✅ Your request to add "${newSubject}" has been sent for admin verification.`, teacherMenu);
    } catch (error) {
        console.error('Error in add subject scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
    }
    ctx.scene.leave();
});
stage.register(addSubjectScene);

// Remove Subject Scene
const removeSubjectScene = new Scenes.BaseScene('remove_subject_scene');
removeSubjectScene.enter(async (ctx) => {
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
            ctx.reply('❌ You have no subjects to remove.', teacherMenu);
            return ctx.scene.leave();
        }
        const subjectButtons = teacher.subjects.map(s => [Markup.button.callback(s, `remove_subject_${s.replace(/ /g, '_')}`)]);
        ctx.reply('📚 Please select the subject you want to remove:', Markup.inlineKeyboard(subjectButtons));
    } catch (error) {
        console.error('Error in remove subject scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
        ctx.scene.leave();
    }
});
stage.register(removeSubjectScene);


// Teacher Announcement Scene
const teacherAnnouncementScene = new Scenes.BaseScene('teacher_announcement_scene');
teacherAnnouncementScene.on('text', async (ctx) => {
    const announcement = ctx.message.text.trim();
    if (!isValidAnnouncementOrMessage(announcement)) {
        ctx.reply('❌ Announcement cannot be empty.');
        return;
    }
    try {
        const user = await getUserById(ctx.from.id);
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        const subject = ctx.session.announcementSubject;
        if (!user || !teacher || !subject) {
            return ctx.reply('❌ An error occurred. Please contact an admin.');
        }
        
        // Find students who have grades in this subject
        const students = await Student.find({
            [`grades.${subject.toLowerCase()}`]: { $exists: true, $ne: [] }
        });
        
        const parentIds = [...new Set(students.map(s => s.parentId).filter(id => id !== null))];
        
        for (const parentId of parentIds) {
            try {
                await ctx.telegram.sendMessage(parentId, `📢 *Message from your child's ${subject} Teacher:*
${announcement}`, { parse_mode: 'Markdown' });
            } catch (error) {
                if (error.response && error.response.error_code === 403) {
                    console.log(`Parent ${parentId} has blocked the bot.`);
                } else {
                    console.error(`Failed to send announcement to parent ${parentId}:`, error);
                }
            }
        }
        ctx.reply('✅ Announcement sent to all parents of your students.', teacherMenu);
    } catch (error) {
        console.error('Error in teacher announcement scene:', error);
        ctx.reply('❌ An error occurred. Please try again.');
    }
    ctx.scene.leave();
});
stage.register(teacherAnnouncementScene);


// --- Menus ---

// Update the admin menu to include the Export IDs option
const adminMenu = Markup.keyboard([
  ['🧑🎓 Students', '👥 Users', '🚫 Ban/Unban Teacher'],
  ['✉️ Contact Teacher', '📞 Contact Parent', '👑 Contact Admins'],
  ['🔍 Search', '📁 Manage Uploads', '📤 Export IDs'],
  ['📢 Announcements']
]).resize();

const userManagementMenu = Markup.keyboard([
    ['✏️ Edit Teacher', '🗑️ Remove Teacher'],
    ['➕ Add Teacher'],
    ['👀 View Admins', '👀 View Teachers', '👀 View Parents'],
    ['⬅️ Back to Admin Menu']
]).resize();

const studentManagementMenu = Markup.keyboard([
    ['➕ Add Student', '➖ Remove Student', '✏️ Edit Student'],
    ['📤 Upload Student List', '🔗 Unbind Parent'],
    ['👀 View All Students', '👀 View All Classes'],
    ['⬅️ Back to Admin Menu']
]).resize();

// --- Menu Definitions ---
const loginMenu = Markup.keyboard([
    ['👨‍🏫 Teacher Registration', '🔐 Teacher Login'],
    ['👤 Parent Registration'],
]).resize();

const parentMenu = Markup.keyboard([
    ['💯 View Grades'],
    ['🧑‍🎓 My Profile', '🔗 Link Another Student'],
    ['💬 Contact Admin']
]).resize();


// Update teacher menu to include logout
const teacherMenu = Markup.keyboard([
    ['📚 My Students', '➕ Add a Student', '🗑️ Remove Student'],
    [ '📖 My Subjects', '📋 Request List', '🔍 Search'],
    ['💬 Contact a Parent', '📢 Announce Parents', '👑 Contact Admin' ],
    ['📊 Manage Grades', '📤 Export Grades'],
    ['🔓 Logout']  // Added logout button
]).resize();
const teacherProfileMenu = Markup.inlineKeyboard([
    [Markup.button.callback('➕ Add New Subject', 'add_new_subject'), Markup.button.callback('➖ Remove Subject', 'remove_subject')],
    [Markup.button.callback('⬅️ Back to Teacher Menu', 'back_to_teacher')]
]);

const parentProfileMenu = Markup.inlineKeyboard([
    [Markup.button.callback('🔗 Linked Students', 'view_linked_children')],
    [Markup.button.callback('⬅️ Back to Parent Menu', 'back_to_parent')]
]);





// --- Bot Commands ---



// --- ADD THIS START COMMAND HANDLER ---
bot.start(async (ctx) => {
    try {
        // Check if user exists in database
        const user = await getUserById(ctx.from.id);
        
        if (user) {
            // User already exists, show appropriate menu based on role
            switch (user.role) {
                case 'teacher':
                    await ctx.reply(`👋 Welcome back, ${user.name}!`, teacherMenu);
                    break;
                case 'admin':
                    await ctx.reply(`👋 Welcome back, Admin ${user.name}!`, adminMenu);
                    break;
                case 'parent':
                    await ctx.reply(`👋 Welcome back, ${user.name}!`, parentMenu);
                    break;
                default:
                    await ctx.reply(`👋 Welcome back!`, loginMenu);
            }
        } else {
            // New user - create basic user record
            const newUser = new User({
                telegramId: ctx.from.id,
                username: ctx.from.username || '',
                name: ctx.from.first_name || 'User',
                role: 'user'
            });
            await newUser.save();
            
            await ctx.reply(
                `👋 Welcome to School System Bot!\n\n` +
                `Please select an option to get started:`,
                loginMenu
            );
        }
    } catch (error) {
        console.error('Error in start command:', error);
        await ctx.reply('❌ An error occurred. Please try again.');
    }
});

bot.action(/^approve_request_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const requestId = ctx.match[1];
  const StudentListRequest = mongoose.model('StudentListRequest');
  const request = await StudentListRequest.findById(requestId);
  if (!request || request.status !== 'pending') {
    return ctx.reply('❌ Request not found or already processed.');
  }

  // Fetch students of requested class
  const students = await Student.find({ class: request.className }).sort({ name: 1 });
  if (students.length === 0) {
    ctx.reply(`❌ No students found in class ${request.className}.`);
    return;
  }

  // Generate student ID file content
  let content = students.map(s => s.studentId).join('\n');

  // Save file temporarily
  const tempDir = './temp_exports';
  if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
  const fileName = `student_ids_${request.className.replace(/\s+/g, '_')}.txt`;
  const filePath = path.join(tempDir, fileName);
  fs.writeFileSync(filePath, content);

  // Add students automatically to TeacherStudent for chosen subject
  const teacher = await Teacher.findOne({ teacherId: request.teacherId });
  const teacherName = teacher ? teacher.name : "Teacher";
  for (const s of students) {
    // Check if relation exists
    const exists = await TeacherStudent.findOne({
      teacherId: request.teacherId,
      studentId: s.studentId,
      subject: request.subject
    });
    if (!exists) {
      const rel = new TeacherStudent({
        teacherId: request.teacherId,
        teacherName,
        studentId: s.studentId,
        studentName: s.name,
        subject: request.subject,
        className: request.className,
        addedDate: new Date()
      });
      await rel.save();
    }
  }

  // Update request status
  request.status = 'approved';
  request.approvalDate = new Date();
  request.approvedBy = ctx.from.id;
  await request.save();

  // Notify teacher with file
  try {
    await ctx.telegram.sendDocument(request.teacherTelegramId, { source: filePath, filename: fileName, caption: `📋 Student IDs for class ${request.className}` });
  } catch (e) {
    console.error('Failed to send student list to teacher:', e);
  }

  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

  await ctx.reply('✅ Request approved and student list sent.');
});

bot.action(/^deny_request_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const requestId = ctx.match[1];
  const StudentListRequest = mongoose.model('StudentListRequest');
  const request = await StudentListRequest.findById(requestId);
  if (!request || request.status !== 'pending') {
    return ctx.reply('❌ Request not found or already processed.');
  }

  request.status = 'denied';
  request.approvalDate = new Date();
  request.approvedBy = ctx.from.id;
  await request.save();

  // Notify teacher about denial
  await ctx.telegram.sendMessage(request.teacherTelegramId, `❌ Your student list request for class ${request.className} and subject ${request.subject} was denied by admin.`);

  await ctx.reply('❌ Request denied and teacher notified.');
});

// --- Input Validation Functions ---
// ... rest of your existing code continues
// Start command - show appropriate menu based on user role
// Start command with dynamic menu


// --- Main Menu Action Handlers ---




bot.action(/^approve_request_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const requestId = ctx.match[1];
  const StudentListRequest = mongoose.model('StudentListRequest');
  const request = await StudentListRequest.findById(requestId);
  if (!request || request.status !== 'pending') {
    return ctx.reply('❌ Request not found or already processed.');
  }

  // Fetch students of requested class
  const students = await Student.find({ class: request.className }).sort({ name: 1 });
  if (students.length === 0) {
    ctx.reply(`❌ No students found in class ${request.className}.`);
    return;
  }

  // Generate student ID file content
  let content = students.map(s => s.studentId).join('\n');

  // Save file temporarily
  const tempDir = './temp_exports';
  if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
  const fileName = `student_ids_${request.className.replace(/\s+/g, '_')}.txt`;
  const filePath = path.join(tempDir, fileName);
  fs.writeFileSync(filePath, content);

  // Add students automatically to TeacherStudent for chosen subject
  const teacher = await Teacher.findOne({ teacherId: request.teacherId });
  const teacherName = teacher ? teacher.name : "Teacher";
  for (const s of students) {
    // Check if relation exists
    const exists = await TeacherStudent.findOne({
      teacherId: request.teacherId,
      studentId: s.studentId,
      subject: request.subject
    });
    if (!exists) {
      const rel = new TeacherStudent({
        teacherId: request.teacherId,
        teacherName,
        studentId: s.studentId,
        studentName: s.name,
        subject: request.subject,
        className: request.className,
        addedDate: new Date()
      });
      await rel.save();
    }
  }

  // Update request status
  request.status = 'approved';
  request.approvalDate = new Date();
  request.approvedBy = ctx.from.id;
  await request.save();

  // Notify teacher with file
  try {
    await ctx.telegram.sendDocument(request.teacherTelegramId, { source: filePath, filename: fileName, caption: `📋 Student IDs for class ${request.className}` });
  } catch (e) {
    console.error('Failed to send student list to teacher:', e);
  }

  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

  await ctx.reply('✅ Request approved and student list sent.');
});

bot.action(/^deny_request_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const requestId = ctx.match[1];
  const StudentListRequest = mongoose.model('StudentListRequest');
  const request = await StudentListRequest.findById(requestId);
  if (!request || request.status !== 'pending') {
    return ctx.reply('❌ Request not found or already processed.');
  }

  request.status = 'denied';
  request.approvalDate = new Date();
  request.approvedBy = ctx.from.id;
  await request.save();

  // Notify teacher about denial
  await ctx.telegram.sendMessage(request.teacherTelegramId, `❌ Your student list request for class ${request.className} and subject ${request.subject} was denied by admin.`);

  await ctx.reply('❌ Request denied and teacher notified.');
});

bot.hears('👤 Parent Registration', async (ctx) => {
  ctx.scene.enter('register_parent_scene');
});


bot.hears('🚫 Ban/Unban Teacher', async (ctx) => {
  const user = await getUserById(ctx.from.id);
  if (!user || user.role !== 'admin') {
    return ctx.reply('❌ You are not authorized to use this feature.');
  }
  const teachers = await Teacher.find().sort({ name: 1 });
  if (teachers.length === 0) {
    return ctx.reply('No teachers found.');
  }

  const buttons = teachers.map(teacher => [
    Markup.button.callback(
      `${teacher.name} (${teacher.teacherId}) - ${teacher.banned ? 'Unban' : 'Ban'}`,
      `${teacher.banned ? 'unban' : 'ban'}_${teacher.teacherId}`
    )
  ]);

  buttons.push([Markup.button.callback('❌ Cancel', 'cancel_ban_unban')]);

  ctx.reply('Select a teacher to ban or unban:', Markup.inlineKeyboard(buttons));
});

// Handle ban/unban actions
bot.action(/^ban_(.+)$/, async (ctx) => {
  const teacherId = ctx.match[1];
  await ctx.answerCbQuery();
  const teacher = await Teacher.findOne({ teacherId });
  if (!teacher) {
    return ctx.reply('❌ Teacher not found.');
  }
  teacher.banned = true;
  await teacher.save();
  ctx.reply(`✅ Teacher ${teacher.name} has been banned from accessing the bot.`);
});

bot.action(/^unban_(.+)$/, async (ctx) => {
  const teacherId = ctx.match[1];
  await ctx.answerCbQuery();
  const teacher = await Teacher.findOne({ teacherId });
  if (!teacher) {
    return ctx.reply('❌ Teacher not found.');
  }
  teacher.banned = false;
  await teacher.save();
  ctx.reply(`✅ Teacher ${teacher.name} has been unbanned and can now access the bot.`);
});

bot.action('cancel_ban_unban', async (ctx) => {
  await ctx.answerCbQuery();
  ctx.reply('Ban/unban operation cancelled.', adminMenu);
});

bot.action('teacher_register', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('teacher_register_start_scene');
});

bot.action('teacher_login', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.scene.enter('teacher_login_scene');
});

bot.action('cancel_operation', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.reply('Operation cancelled.', Markup.removeKeyboard());
});

// Handle text commands for teacher registration and login
bot.hears('👨‍🏫 Teacher Registration', async (ctx) => {
    ctx.scene.enter('teacher_register_start_scene');
});

bot.hears('🔐 Teacher Login', async (ctx) => {
    ctx.scene.enter('teacher_login_scene');
});


bot.hears('📋 Request List', async (ctx) => {
  const user = await getUserById(ctx.from.id); // Retrieve user info to check role
  if (user && user.role === 'teacher') {
    if (ctx.scene && ctx.scene.session) {
      await ctx.scene.leave(); // Reset previous scene state if any
    }
    await ctx.scene.enter('request_students_list_scene'); // Enter the scene
  } else {
    await ctx.reply('❌ You are not authorized to use this feature.');
  }
});

// Handle logout command
bot.hears('🚪 Logout', async (ctx) => {
    // Clear session data
    ctx.session = null;
    ctx.reply('✅ Successfully logged out. Please log in again to access teacher features.', loginMenu);
});
// Help command
bot.hears('ℹ️ Help', (ctx) => {
    ctx.reply(
        '🤖 School System Bot Help\n\n' +
        '• Register as Teacher: Start the teacher registration process\n' +
        '• Teacher Login: Log in to your teacher account\n' +
        '• Contact Admin: Get assistance from administrators\n\n' +
        'For technical issues, please contact the system administrator.'
    );
});
// Handle unknown callback queries


// Handle unhandled actions
bot.catch((err, ctx) => {
    console.error('Bot error:', err);
    ctx.reply('❌ An error occurred. Please try again.');
});
bot.command('admin', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        return ctx.reply('⚙️ Admin Panel', adminMenu);
    }
    ctx.scene.enter('admin_login_scene');
});
// Add this command handler


// --- Text/Keyboard Handlers ---
// Teacher Logout Handler - Fixed to maintain proper state
bot.hears('🔓 Logout', async (ctx) => {
  try {
    // Remove Telegram link safely
    await Teacher.updateOne(
      { telegramId: ctx.from.id },
      { $unset: { telegramId: "" } }
    );

    // If you have user/admin updates
    await User.updateOne(
      { adminId: ctx.from.id },
      { $unset: { adminId: "" } }
    );

    // Send message with a new keyboard having only the login button for teachers
    await ctx.reply(
      "✅ You have been logged out successfully. Please log in again.",
      Markup.keyboard([['🔐 Login']]).resize()
    );
  } catch (err) {
    console.error("Logout error:", err);
    await ctx.reply("Something went wrong during logout.");
  }
});
bot.hears('🔐 Login', async (ctx) => {
  ctx.scene.enter('teacher_login_scene'); // or the scene handling teacher login
});



// Add handler for the new menu option
bot.hears('👑 Contact Admin', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_contact_admin_scene');
    } else {
        ctx.reply('❌ You are not authorized to contact admins.');
    }
});
// Add handler for the new menu option
bot.hears('📤 Export Grades', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_export_grades_scene');
    } else {
        ctx.reply('❌ You are not authorized to export grades.');
    }
});
// Add handler for the new menu option
bot.hears('🔍 Search', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_search_student_scene');
    } else {
        ctx.reply('❌ You are not authorized to search students.');
    }
});
// Add handler for the new menu option
bot.hears('💬 Contact a Parent', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_contact_parent_scene');
    } else {
        ctx.reply('❌ You are not authorized to contact parents.');
    }
});
// Add handler for the new menu option
bot.hears('🗑️ Remove Student', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_remove_student_scene');
    } else {
        ctx.reply('❌ You are not authorized to remove students.');
    }
});
// Add handler for the new menu option
bot.hears('📢 Announce Parents', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('announce_class_scene');
    } else {
        ctx.reply('❌ You are not authorized to send announcements.');
    }
});
// Add handler for the new menu option
bot.hears('📖 My Subjects', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_my_subjects_scene');
    } else {
        ctx.reply('❌ You are not authorized to manage subjects.');
    }
});
bot.hears('📊 Manage Grades', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('manage_grades_scene');
    } else {
        ctx.reply('❌ You are not authorized to manage grades.');
    }
});
bot.hears('📋 Upload Student List', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_upload_students_scene');
    } else {
        ctx.reply('❌ You are not authorized to upload student lists.');
    }
});
// Contact Admins menu handler
bot.hears('👑 Contact Admins', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('contact_admins_scene');
    } else {
        ctx.reply('❌ You are not authorized to contact admins.');
    }
});
bot.hears('📞 Contact Parent', async (ctx) => {
  const user = await getUserById(ctx.from.id);
  if (user && user.role === 'admin') {
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('contact_parent_admin_scene');
  } else {
    ctx.reply('❌ You are not authorized to contact parents.');
  }
});
bot.hears('✉️ Contact Teacher', async (ctx) => {
  const user = await getUserById(ctx.from.id);
  if (user && user.role === 'admin') {
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('contact_teacher_scene');
  } else {
    ctx.reply('❌ You are not authorized to contact teachers.');
  }
});

bot.hears('🗑️ Remove Teacher', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('remove_teacher_scene');
    } else {
        ctx.reply('❌ You are not authorized to remove teachers.');
    }
});
// Export IDs menu handler
bot.hears('📤 Export IDs', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('export_ids_scene');
    } else {
        ctx.reply('❌ You are not authorized to use this feature.');
    }
});

bot.hears('👀 View All Classes', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        const availableClasses = await getUniqueClasses();
        
        if (availableClasses.length === 0) {
            ctx.reply('No classes found. Please upload a student list first.');
            return;
        }
        
        const classList = availableClasses.map((className, index) => 
            `${index + 1}. ${className}`
        ).join('\n');
        
        ctx.reply(`📚 Available Classes:\n\n${classList}`);
    }
});
bot.hears('🧑🎓 Students', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        ctx.reply('🧑‍🎓 Student Management:', studentManagementMenu);
    }
});

bot.hears('👥 Users', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        ctx.reply('👥 User Management:', userManagementMenu);
    }
});

bot.hears('📢 Announcements', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        ctx.scene.enter('announcement_recipient_scene');
    } else {
        ctx.reply('❌ You do not have permission to send announcements.');
    }
});

bot.hears('🔍 Search', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && (user.role === 'admin')) {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('search_admin_scene');
    } else {
        ctx.reply('❌ You are not authorized to use this feature.');
    }
});

bot.hears('📁 Manage Uploads', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        try {
            const uploadedFiles = await UploadedFile.find();
            if (uploadedFiles.length === 0) {
                ctx.reply('📂 No files have been uploaded yet.');
                return;
            }
            let fileList = '*Uploaded Files:*';
            uploadedFiles.forEach(file => {
                const status = file.processed ? '✅ Processed' : '⏳ Pending';
                const classInfo = file.classAssigned ? ` (Class: ${file.classAssigned})` : '';
                fileList += `• *${file.originalName}*
  ID: ${file.id}
  Upload Date: ${new Date(file.uploadDate).toLocaleString()}
  Status: ${status}${classInfo}
`;
            });
            const deleteButtons = uploadedFiles.map(file =>
                [Markup.button.callback(`🗑️ Delete ${file.originalName}`, `delete_file_${file.id}`)]
            );
            ctx.replyWithMarkdown(fileList, Markup.inlineKeyboard(deleteButtons));
        } catch (error) {
            console.error('Error managing uploads:', error);
            ctx.reply('❌ An error occurred while retrieving uploaded files.');
        }
    } else {
        ctx.reply('❌ You are not authorized to manage uploads.');
    }
});


bot.hears('➕ Add Teacher', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('add_teacher_scene');
    }
});


// Edit Teacher menu handler
bot.hears('✏️ Edit Teacher', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('edit_teacher_scene');
    }
});

bot.hears('👀 View Admins', async (ctx) => {
    try {
        const admins = await getAdmins();
        if (admins.length > 0) {
            const adminList = admins.map(u => `ID: ${u.telegramId}, Name: ${u.name}`).join('');
            ctx.replyWithMarkdown(`**Current Admins:**
${adminList}`);
        } else {
            ctx.reply('No admins found.');
        }
    } catch (error) {
        console.error('Error viewing admins:', error);
        ctx.reply('❌ An error occurred while retrieving admins.');
    }
});

bot.hears('👀 View Teachers', async (ctx) => {
  try {
    const teachers = await Teacher.find();
    if (teachers.length === 0) {
      return ctx.reply('No teachers found.');
    }

    let message = '**All Teachers:**\n\n';
    teachers.forEach(t => {
      const subjects = t.subjects.length > 0 ? t.subjects.join(', ') : 'N/A';
      const telegramId = t.telegramId || 'N/A';
      message += `• ID: ${t.teacherId}\n  Name: ${t.name}\n  Subjects: ${subjects}\n  Telegram ID: ${telegramId}\n\n`;
    });

    ctx.replyWithMarkdown(message);
  } catch (error) {
    console.error('Error viewing teachers:', error);
    ctx.reply('❌ An error occurred while retrieving teachers.');
  }
});


bot.hears('👀 View Parents', async (ctx) => {
  try {
    const parents = await User.find({ role: 'parent' });
    if (parents.length === 0) {
      return ctx.reply('No parents found.');
    }

    let content = `Parents List - Total: ${parents.length}\n\n`;
    content += 'Telegram ID | Name | Linked Students Count\n';
    content += '--------------------------------------\n';
    parents.forEach(p => {
      const linkedCount = p.studentIds ? p.studentIds.length : 0;
      content += `${p.telegramId} | ${p.name} | ${linkedCount}\n`;
    });

    const fs = require('fs');
    const path = require('path');
    const tempDir = './temp_exports';
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
    const filePath = path.join(tempDir, `parents_list_${Date.now()}.txt`);
    fs.writeFileSync(filePath, content);

    await ctx.replyWithDocument({ source: filePath, filename: 'parents_list.txt' }, { caption: `📋 Detailed list of parents (${parents.length} total)` });

    // Clean up the file after sending
    fs.unlinkSync(filePath);

  } catch (error) {
    console.error('Error viewing parents:', error);
    ctx.reply('❌ An error occurred while retrieving parents.');
  }
});


bot.hears('🔗 Unbind Parent', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('unbind_parent_scene');
    }
});

bot.hears('➕ Add Student', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('add_student_scene');
    }
});

bot.hears('➖ Remove Student', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('remove_student_scene');
    }
});

bot.hears('✏️ Edit Student', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('edit_student_scene');
    }
});

bot.hears('📤 Upload Student List', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('upload_student_list_scene');
    }
});

// View All Students menu handler
bot.hears('👀 View All Students', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'admin') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('view_students_by_grade_scene');
    } else {
        ctx.reply('❌ You are not authorized to use this feature.');
    }
});
bot.hears('⬅️ Back to Admin Menu', (ctx) => {
    ctx.reply('⬅️ Returning to admin menu.', adminMenu);
});

   bot.hears('💯 View Grades', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'parent') {
        if (ctx.scene?.session) ctx.scene.leave();
        try {
            const students = await getStudentsByParentId(user.telegramId);
            if (students.length === 0) {
                return ctx.reply('❌ You are not linked to any students.');
            }
            
            let fullGradeList = '📋 *Your Child(ren)\'s Grades:*\n\n';
            
            for (const student of students) {
                const result = await viewStudentGrades(student.studentId);
                if (!result) continue;
                
                fullGradeList += `--- *${student.name}* (Class: ${student.class || 'N/A'}) ---\n`;
                
                if (result.grades.length === 0) {
                    fullGradeList += 'No grades found.\n\n';
                } else {
                    // Group grades by subject
                    const gradesBySubject = {};
                    result.grades.forEach(grade => {
                        if (!gradesBySubject[grade.subject]) {
                            gradesBySubject[grade.subject] = [];
                        }
                        gradesBySubject[grade.subject].push(grade);
                    });
                    
                    for (const [subject, subjectGrades] of Object.entries(gradesBySubject)) {
                        fullGradeList += `*${subject}:*\n`;
                        subjectGrades.forEach(gradeInfo => {
                            fullGradeList += ` - Score: ${gradeInfo.score}, Purpose: ${gradeInfo.purpose}, Date: ${new Date(gradeInfo.date).toLocaleDateString()}\n`;
                        });
                        fullGradeList += '\n';
                    }
                }
            }
            
            return ctx.replyWithMarkdown(fullGradeList);
        } catch (error) {
            console.error('Error viewing grades:', error);
            ctx.reply('❌ An error occurred while retrieving grades.');
        }
    } else {
        ctx.reply('❌ You are not authorized to view grades.');
    }
});
bot.hears('💬 Contact Admin', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'parent') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('contact_admin_scene');
    } else {
        ctx.reply('❌ You are not authorized to contact admins.');
    }
});



bot.hears('🔗 Link Another Student', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'parent') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('link_another_student_scene');
    } else {
        ctx.reply('❌ You must be a parent to link students.');
    }
});

// Update the teacher menu handlers

// Add handler for the new menu option
bot.hears('➕ Add a Student', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_add_student_scene');
    } else {
        ctx.reply('❌ You are not authorized to add students.');
    }
});
bot.hears('📚 My Students', requireTeacherAuth, async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('teacher_my_students_scene');
    } else {
        ctx.reply('❌ You are not authorized to manage students.');
    }
});

bot.hears('💬 Contact Parent', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('contact_parent_scene');
    } else {
        ctx.reply('❌ You are not authorized to contact parents.');
    }
});

bot.hears('🔍 Search', async (ctx) => {
    const user = await getUserById(ctx.from.id);
    if (user && user.role === 'teacher') {
        if (ctx.scene?.session) ctx.scene.leave();
        ctx.scene.enter('search_scene');
    } else {
        ctx.reply('❌ You are not authorized to use this feature.');
    }
});

// --- Action Handlers ---


// Admin command to resend OTP
bot.action(/^resend_otp_(\d+)$/, async (ctx) => {
    await ctx.answerCbQuery();
    const telegramId = ctx.match[1];
    
    const otpRecord = await OTP.findOne({ telegramId });
    if (!otpRecord) {
        ctx.reply('❌ No pending registration found for this user.');
        return;
    }
    
    // Generate new OTP
    const newOTP = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    
    otpRecord.otp = newOTP;
    otpRecord.expiresAt = expiresAt;
    otpRecord.attempts = 0;
    otpRecord.verified = false;
    await otpRecord.save();
    
    ctx.reply(
        `🔐 New OTP generated for user ${telegramId}:\n\n` +
        `OTP: ${newOTP}\n` +
        `Expires: ${expiresAt.toLocaleTimeString()}`
    );
    
    // Edit original message to show new OTP
    try {
        await ctx.editMessageText(
            ctx.update.callback_query.message.text + `\n\n🔄 OTP Resent: ${newOTP}`,
            { parse_mode: 'Markdown' }
        );
    } catch (error) {
        console.error('Error editing message:', error);
    }
});

// Admin command to cancel registration
bot.action(/^cancel_registration_(\d+)$/, async (ctx) => {
    await ctx.answerCbQuery();
    const telegramId = ctx.match[1];
    
    await OTP.deleteOne({ telegramId });
    ctx.reply(`✅ Registration cancelled for user ${telegramId}.`);
    
    // Edit original message
    try {
        await ctx.editMessageText(
            ctx.update.callback_query.message.text + '\n\n❌ Registration Cancelled',
            { parse_mode: 'Markdown' }
        );
    } catch (error) {
        console.error('Error editing message:', error);
    }
});
// Helper function to view grades

bot.action('teacher_my_subjects', async (ctx) => {
    await ctx.answerCbQuery(); // Acknowledge the button click
    try {
        // Ensure any previous scene is left
        if (ctx.scene?.session) ctx.scene.leave();

        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });

        if (!teacher) {
            return ctx.reply('❌ Teacher record not found. Please contact an admin.');
        }

        // Display the subjects list scene
        await ctx.scene.enter('teacher_my_subjects_scene');

    } catch (error) {
        console.error('Error handling teacher_my_subjects action:', error);
        await ctx.reply('❌ An error occurred. Please try again.');
    }
});


bot.action('register_parent', async (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('register_parent_scene');
});

bot.action(/^announce_subject_(.+)$/, (ctx) => {
    const subject = ctx.match[1].replace(/_/g, ' ');
    ctx.session.announcementSubject = subject;
    ctx.answerCbQuery();
    ctx.reply(`📢 Please type the announcement to send to the parents of your students in ${subject}.`);
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('teacher_announcement_scene');
});

bot.action(/^manage_grades_(\d+)$/, (ctx) => {
    const studentId = ctx.match[1];
    ctx.session.currentStudentId = studentId;
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('manage_grades_scene');
});

bot.action('view_linked_children', async (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    try {
        const parent = await User.findOne({ telegramId: ctx.from.id, role: 'parent' });
        if (parent) {
            const studentIds = parent.studentIds || [];
            if (studentIds.length === 0) {
                return ctx.reply('You are not linked to any students.');
            }
            const students = await Promise.all(studentIds.map(id => getStudentById(id)));
            const validStudents = students.filter(s => s);
            if (validStudents.length === 0) {
                return ctx.reply('You are not linked to any valid students.');
            }
            const studentList = validStudents.map(s => `• Name: ${s.name}, ID: ${s.studentId}, Class: ${s.class || 'N/A'}`).join('');
            ctx.replyWithMarkdown(`**Linked Students:**
${studentList}`);
        } else {
            ctx.reply('❌ Your profile could not be found.');
        }
    } catch (error) {
        console.error('Error viewing linked children:', error);
        ctx.reply('❌ An error occurred while retrieving your linked students.');
    }
});

bot.action('add_new_subject', (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('add_subject_scene');
});

bot.action('remove_subject', (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('remove_subject_scene');
});

bot.action('teacher_add_student', (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('teacher_add_student_scene');
});

bot.action('teacher_remove_student', (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('teacher_remove_student_scene');
});

bot.action('back_to_teacher', (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.reply('⬅️ Returning to teacher menu.', teacherMenu);
});

bot.action('back_to_parent', (ctx) => {
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.reply('⬅️ Returning to parent menu.', parentMenu);
});

// Update the action handlers in your main bot code
bot.action('edit_student_name', async (ctx) => {
    await ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('edit_student_name_scene');
});

bot.action('edit_student_class', async (ctx) => {
    await ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('edit_student_class_scene'); // Changed to new scene
});

// Action handler for edit student parent
bot.action('edit_student_parent', async (ctx) => {
    await ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('edit_student_parent_scene');
});
// Action handlers for edit teacher options
bot.action('edit_teacher_name', async (ctx) => {
    await ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('edit_teacher_name_scene');
});

bot.action('edit_teacher_subjects', async (ctx) => {
    await ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('edit_teacher_subjects_scene');
});
bot.action('edit_teacher_telegram', async (ctx) => {
    await ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
    ctx.scene.enter('edit_teacher_telegram_scene');
});

bot.action(/^remove_subject_(.+)$/, async (ctx) => {
    const subjectToRemove = ctx.match[1].replace(/_/g, ' ');
    try {
        const teacher = await Teacher.findOne({ telegramId: ctx.from.id });
        if (teacher) {
            teacher.subjects = teacher.subjects.filter(s => s !== subjectToRemove);
            await teacher.save();
            
            const user = await getUserById(teacher.telegramId);
            if (user) {
                user.subjects = user.subjects.filter(s => s !== subjectToRemove);
                await user.save();
            }
            ctx.reply(`✅ Subject "${subjectToRemove}" has been removed from your profile.`, teacherMenu);
        } else {
            ctx.reply('❌ An error occurred. Subject not found.', teacherMenu);
        }
    } catch (error) {
        console.error('Error removing subject:', error);
        ctx.reply('❌ An error occurred while removing the subject.', teacherMenu);
    }
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
});

bot.action(/^approve_subject_(TE\d+)_(.+)$/, async (ctx) => {
    const teacherId = ctx.match[1];
    const subject = ctx.match[2].replace(/_/g, ' ');
    try {
        const teacher = await getTeacherById(teacherId);
        if (teacher && teacher.pendingSubjects && teacher.pendingSubjects.includes(subject)) {
            teacher.subjects.push(subject);
            teacher.pendingSubjects = teacher.pendingSubjects.filter(s => s !== subject);
            await teacher.save();
            
            const user = await getUserById(teacher.telegramId);
            if (user) {
                user.subjects.push(subject);
                await user.save();
                ctx.replyWithMarkdown(`✅ Subject **${subject}** has been approved for **${teacher.name}**.`);
                try {
                    ctx.telegram.sendMessage(user.telegramId, `✅ Your request to add subject "${subject}" has been approved by an admin!`);
                } catch (e) { /* ignore */ }
            }
        } else {
            ctx.reply('❌ Request not found.');
        }
    } catch (error) {
        console.error('Error approving subject:', error);
        ctx.reply('❌ An error occurred while approving the subject.');
    }
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
});

bot.action(/^deny_subject_(TE\d+)_(.+)$/, async (ctx) => {
    const teacherId = ctx.match[1];
    const subject = ctx.match[2].replace(/_/g, ' ');
    try {
        const teacher = await getTeacherById(teacherId);
        if (teacher && teacher.pendingSubjects && teacher.pendingSubjects.includes(subject)) {
            teacher.pendingSubjects = teacher.pendingSubjects.filter(s => s !== subject);
            await teacher.save();
            
            const user = await getUserById(teacher.telegramId);
            ctx.replyWithMarkdown(`❌ Subject **${subject}** has been denied for **${teacher.name}**.`);
            try {
                ctx.telegram.sendMessage(user.telegramId, `❌ Your request to add subject "${subject}" has been denied by an admin.`);
            } catch (e) { /* ignore */ }
        } else {
            ctx.reply('❌ Request not found.');
        }
    } catch (error) {
        console.error('Error denying subject:', error);
        ctx.reply('❌ An error occurred while denying the subject.');
    }
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
});

// Admin approval handler for parent requests
bot.action(/^approve_parent_(\d+)_(.+)$/, async (ctx) => {
    await ctx.answerCbQuery();
    
    const parentId = ctx.match[1];
    const studentId = ctx.match[2];
    
    try {
        const parent = await getUserById(parentId);
        const student = await getStudentById(studentId);
        
        if (!parent || !student) {
            return ctx.reply('❌ Parent or student not found.');
        }
        
        // Update parent role and student list
        parent.role = 'parent';
        if (!parent.studentIds) parent.studentIds = [];
        if (!parent.studentIds.includes(studentId)) {
            parent.studentIds.push(studentId);
        }
        parent.pendingStudentIds = parent.pendingStudentIds.filter(id => id !== studentId);
        await parent.save();
        
        // Update student record
        student.parentId = parentId;
        student.pendingParentId = null;
        await student.save();
        
        // Notify parent
        try {
            await ctx.telegram.sendMessage(
                parentId,
                `✅ *Parent Registration Approved!*\n\n` +
                `You are now linked to student:\n` +
                `• Name: ${student.name}\n` +
                `• ID: ${student.studentId}\n` +
                `• Class: ${student.class}\n\n` +
                `You can now access their grades and school information.`,
                { parse_mode: 'Markdown' }
            );
        } catch (error) {
            console.error(`Failed to notify parent ${parentId}:`, error);
        }
        
        // Update admin message
        await ctx.editMessageText(
            `✅ Approved: ${parent.name} → ${student.name}\n` +
            `Parent can now access student information.`,
            { reply_markup: { inline_keyboard: [] } }
        );
        
    } catch (error) {
        console.error('Error approving parent:', error);
        ctx.reply('❌ An error occurred while approving the parent.');
    }
});

// Admin denial handler for parent requests
bot.action(/^deny_parent_(\d+)_(.+)$/, async (ctx) => {
    await ctx.answerCbQuery();
    
    const parentId = ctx.match[1];
    const studentId = ctx.match[2];
    
    try {
        const parent = await getUserById(parentId);
        const student = await getStudentById(studentId);
        
        if (parent) {
            parent.pendingStudentIds = parent.pendingStudentIds.filter(id => id !== studentId);
            await parent.save();
        }
        
        if (student) {
            student.pendingParentId = null;
            await student.save();
        }
        
        // Notify parent
        try {
            await ctx.telegram.sendMessage(
                parentId,
                `❌ *Parent Registration Denied*\n\n` +
                `Your request to link with student ${studentId} has been denied by an administrator.\n` +
                `Please contact the school administration for more information.`
            );
        } catch (error) {
            console.error(`Failed to notify parent ${parentId}:`, error);
        }
        
        // Update admin message
        await ctx.editMessageText(
            `❌ Denied: Parent request for student ${studentId}\n` +
            `Parent has been notified.`,
            { reply_markup: { inline_keyboard: [] } }
        );
        
    } catch (error) {
        console.error('Error denying parent:', error);
        ctx.reply('❌ An error occurred while denying the parent.');
    }
});

bot.action(/^deny_parent_(\d+)_(\d+)$/, async (ctx) => {
    const parentIdStr = ctx.match[1];
    const studentId = ctx.match[2];
    const parentId = parentIdStr;
    
    if (!isValidTelegramId(parentIdStr) || !isValidStudentId(studentId)) {
        ctx.reply('❌ Invalid request data.');
        ctx.answerCbQuery();
        return;
    }
    
    try {
        const parent = await getUserById(parentId);
        const student = await getStudentById(studentId);
        
        if (parent && student && student.pendingParentId === parentId) {
            student.pendingParentId = null;
            await student.save();
            
            if (parent.pendingStudentIds) {
                parent.pendingStudentIds = parent.pendingStudentIds.filter(id => id !== studentId);
            }
            if (parent.studentIds && parent.studentIds.length === 0 && 
                parent.pendingStudentIds && parent.pendingStudentIds.length === 0) {
                parent.role = 'user';
            }
            await parent.save();
            
            ctx.replyWithMarkdown(`❌ Parent ${parent.name} link request for student ${student.name} has been denied.`);
            try {
                ctx.telegram.sendMessage(parentId, `❌ Your request to link with student ${student.name} (ID: ${studentId}) has been denied.`);
            } catch (e) { /* ignore */ }
        } else {
            ctx.reply('❌ Request not found or already processed.');
        }
    } catch (error) {
        console.error('Error denying parent:', error);
        ctx.reply('❌ An error occurred while denying the parent request.');
    }
    ctx.answerCbQuery();
    if (ctx.scene?.session) ctx.scene.leave();
});

bot.action(/^delete_file_(.+)$/, async (ctx) => {
    const fileIdToDelete = ctx.match[1];
    const user = await getUserById(ctx.from.id);
    
    if (user && user.role === 'admin') {
        try {
            const result = await UploadedFile.deleteOne({ id: fileIdToDelete });
            if (result.deletedCount > 0) {
                ctx.reply(`🗑️ File has been deleted.`);
            } else {
                ctx.reply('❌ File not found.');
            }
        } catch (error) {
            console.error('Error deleting file:', error);
            ctx.reply('❌ An error occurred while deleting the file.');
        }
    } else {
        ctx.reply('❌ You are not authorized to delete files.');
    }
    ctx.answerCbQuery();
});
// --- Launch bot ---
// Run migration first, then start the bot
const startBot = async () => {
    try {
        
        bot.launch();
        console.log('✅ Bot is now live and listening...');
    } catch (error) {
        console.error('❌ Error starting bot:', error);
    }
};

// Clean up existing users with undefined adminId

startBot();

process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));