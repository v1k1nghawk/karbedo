#include "mainwindow.h"
#include "ui_mainwindow.h"


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    QThread::currentThread()->setObjectName(APP_NAME+"_GUI");
    ui->setupUi(this);
    ui->usersCBox->hide();
    ui->stopButton->hide();

    // GUI->buttons
    QObject::connect(ui->openFileButton, SIGNAL(clicked()), this, SLOT(openFileButton_clicked()), Qt::DirectConnection);

    // prepare to run updater in a separete thread
    this->m_update_thread = new QThread(this);
    this->m_updateobj = new guiUpdater(Q_NULLPTR);
    this->m_updateobj->moveToThread(this->m_update_thread);
    // updater thread <-> updater obj
    QObject::connect(this->m_update_thread, SIGNAL(started()), this->m_updateobj, SLOT(run_update()));
    QObject::connect(this->m_update_thread, SIGNAL(finished()), this->m_updateobj, SLOT(deleteLater()));
    QObject::connect(this->m_updateobj, SIGNAL(signal_updateFinished()), this->m_update_thread, SLOT(quit()));
    // GUI<->updater
    QObject::connect(this, SIGNAL(signal_stopGuiUpdater()), this->m_updateobj, SLOT(stopUpdate()), Qt::QueuedConnection);
    QObject::connect(this->m_updateobj, SIGNAL(signal_computing()), this, SLOT(statusUpdate()), Qt::QueuedConnection);
    QObject::connect(this->m_updateobj, SIGNAL(signal_pwfound(const QString&)), this, SLOT(infodeskUpdate(const QString&)), Qt::QueuedConnection);
    QObject::connect(this->m_updateobj, SIGNAL(signal_repaint()), this, SLOT(repaint()), Qt::QueuedConnection);

    // run
    this->m_update_thread->start();

    ui->StatusLabel->setText("Date: " + QDate::currentDate().toString("dd.MM.yyyy"));
}


MainWindow::~MainWindow()
{
    // stop and destruct updater
    emit signal_stopGuiUpdater();
    destroyThread(m_update_thread);
    this->m_updateobj = Q_NULLPTR;

    delete ui;
}


void MainWindow::openFileButton_clicked()
{
    ui->GeneralTE->clear();

    // choose file
    QString fileName = QFileDialog::getOpenFileName(this, "Select a file to open...", QDir::homePath());
    if (fileName == "") {
        ui->StatusLabel->setText("File: no file name specified");
        return;
    }

    ui->StatusLabel->setText("File: " + fileName);

    // read file
    unsigned int lineCounter = 1;
    QFile inputFile(fileName);
    if (inputFile.open(QIODevice::ReadOnly))
    {
        // restore system initial state
        m_shadowUsers.clear();
        ui->usersCBox->clear();
        m_initialsetup_usersCBox = 1;

        // populate users' db
        QTextStream in(&inputFile);
        while (!in.atEnd())
        {
            QString shadowFileLine = in.readLine();

            // collect usernames with their data
            QRegExp rxdelim_userfields("\\:");
            QStringList splittedLine = shadowFileLine.split(rxdelim_userfields);

            QString current_username;
            QString current_algnum;
            QString current_salt;
            QString current_hashofpass;

            try {
                current_username = "";
                current_algnum = "";
                current_salt = "";
                current_hashofpass = "";

                // incorrect data for some user
                if (splittedLine.count() != 9)
                    throw ShadowParsingException{fileName + "corrupted at line " + lineCounter};

                // user
                current_username = splittedLine.at(0);

                QRegExp rxdelim_passfields("\\$");
                QStringList current_user_data = splittedLine.at(1).split(rxdelim_passfields);

                // incomplete data format (maybe service credentials)
                if (current_user_data.size() != 4)
                    continue;

                // user's data
                current_algnum = current_user_data.at(1);
                current_salt = current_user_data.at(2);
                current_hashofpass = current_user_data.at(3);

                // unsupported hash algorithm
                if (user::getAlgorithmName(current_algnum) == "")
                    throw ShadowParsingException{"user " + current_username + " has unsupported encryption method (scheme id=" + current_algnum + ")"};

                // add user to db
                m_shadowUsers.push_back(user(current_username, current_algnum, current_salt, current_hashofpass));

            } catch (ShadowParsingException &se)
            {
                ui->GeneralTE->append("Warning: " + QString(se.what()));
            }

            lineCounter++;
        }
        inputFile.close();
    } else {
        ui->StatusLabel->setText("Cannot open file: " + fileName);
    }

    // show usernames
    ui->retranslateUi(this);
    if (m_shadowUsers.empty())
    {
        ui->StatusLabel->setText("File: " + fileName + " there is no correct lines");
    }
    else
    {
        QStringList usersList;
        for (int i = 0; i < m_shadowUsers.size(); ++i)
            usersList.append(m_shadowUsers[i].getUsername());

        QStringListModel *usersModel = new QStringListModel();
        usersModel->setStringList(usersList);
        usersModel->sort(0);

        ui->usersCBox->setModel(usersModel);
        ui->usersCBox->show();

        ui->StatusLabel->setText("File: " + fileName + " parsed");
    }

}


void MainWindow::on_usersCBox_currentTextChanged()
{
    // skip first fire
    if (m_initialsetup_usersCBox == 1)
    {
        m_initialsetup_usersCBox = 0;
        return;
    }

    // get chosen user
    QString selected_username = ui->usersCBox->currentText();

    // prepare GUI for calculations
    ui->GeneralTE->clear();
    ui->usersCBox->hide();
    ui->openFileButton->hide();
    ui->stopButton->show();
    ui->StatusLabel->setText("Performing computations");
    QApplication::setOverrideCursor(Qt::BusyCursor);

    // get chosen user's data
    m_selecteduserobj = new user(Q_NULLPTR);
    for (int i = 0; i < m_shadowUsers.size(); ++i) {
        if (m_shadowUsers[i].getUsername() == selected_username)
        {
            m_selecteduserobj = new user(m_shadowUsers.at(i));
            break;
        }
    }

    // display target's data
    ui->GeneralTE->append("User: " + m_selecteduserobj->getUsername());
    ui->GeneralTE->append("Hash scheme: " + user::getAlgorithmName(m_selecteduserobj->getUseralgid()));
    ui->GeneralTE->append("Salt: " + m_selecteduserobj->getUsersalt());
    ui->GeneralTE->append("Hash:");
    ui->GeneralTE->append(m_selecteduserobj->getUserhash());
    ui->GeneralTE->append("Possible passwords:");
    repaint();

    // prepare to run user's attack in a separete thread
    m_user_thread = new QThread(this);
    m_selecteduserobj->moveToThread(m_user_thread);
    // user thread <-> user obj
    QObject::connect(m_user_thread, SIGNAL(started()), m_selecteduserobj, SLOT(collision_attack()));
    QObject::connect(m_user_thread, SIGNAL(finished()), m_selecteduserobj, SLOT(deleteLater()));
    QObject::connect(m_selecteduserobj, SIGNAL(signal_attackFinished()), m_user_thread, SLOT(quit()));

    // run hash collisions finding
    m_computation_timer.start();
    m_user_thread->start();
}


void MainWindow::on_stopButton_clicked()
{
    stopActions();
}


void MainWindow::stopActions()
{
    // stop and destruct target's calculations
    m_selecteduserobj->attack_interrupt();
    destroyThread(m_user_thread);
    m_selecteduserobj = Q_NULLPTR;

    // show results
    ui->StatusLabel->setText("Found " + QString::number(collisionAttackTask_CPU::getHitsNum()) + " collisions in " + QString::number(m_computation_timer.elapsed()/1000) + " sec");
    m_computation_timer.invalidate();

    // restore GUI initial state
    ui->usersCBox->show();
    ui->openFileButton->show();
    ui->stopButton->hide();
    QApplication::restoreOverrideCursor();
}


void MainWindow::infodeskUpdate(const QString& new_password)
{
    // check that it is a brand new finding
    QStringList all_TE_lines = ui->GeneralTE->toPlainText().split(QRegExp("[\n]"),QString::SkipEmptyParts);
    int TE_last_element = all_TE_lines.size() - 1;
    for (int line_index = TE_last_element; line_index >= 0; line_index--)
    {
        if (all_TE_lines.at(line_index) == new_password)
        {
            return;
        }
        else if (all_TE_lines.at(line_index) == QString("Possible passwords:"))
        {
            break;
        }
    }

    ui->GeneralTE->append(new_password);
    repaint();
}


void MainWindow::statusUpdate()
{
    QMutexLocker status_locker(&m_status_mutex);

    QString current_status = ui->StatusLabel->text();
    QString result_status = QString("");
    QString busychar = QString(".");
    uint busychar_counter = 0;

    // count
    for (QString::const_iterator itr = current_status.end() - 1; itr != current_status.begin(); itr--)
    {
        if (*itr == busychar)
            busychar_counter++;
        else
            break;
    }

    // spinning
    if (busychar_counter >= 3)
        result_status = current_status.left(current_status.length() - busychar_counter);
    else
        result_status = current_status + busychar;

    ui->StatusLabel->setText(result_status);
    repaint();
}


void MainWindow::destroyThread(QThread* del_thread)
{
    del_thread->quit();
    if (!del_thread->wait(5000))
    {
        del_thread->terminate();
        del_thread->wait();
    }
    delete del_thread;
    del_thread = Q_NULLPTR;
}
