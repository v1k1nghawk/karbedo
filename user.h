#ifndef USER_H
#define USER_H

#include "collisionAttackTask_CPU.h"


/**
 * @class user
 * @brief Description of attack's target
 */
class user : public QObject
{
    Q_OBJECT

public:
    user(const QString& username="", const QString& algid="", const QString& salt="", const QString& hashofpass="", QObject *parent=Q_NULLPTR);

    /**
    * @brief Implemented for connection registeration.
    */
    user(const user& other);

    /**
    * @brief Implemented for connection registeration.
    */
    ~user() {}

    /**
    * @brief Assignment.
    */
    user operator=(const user& other);

    /**
    * @brief Setter of the user's data.
    */
    void setUser(const QString& username, const QString& algid, const QString& salt, const QString& hashofpass);

    /**
    * @brief Getter of the user's name.
    * @return User's name.
    */
    QString getUsername() const {return m_username;}

    /**
    * @brief Gets user's hashing algorithm (scheme) ID.
    * @return User's hashing algorithm (scheme) ID.
    */
    QString getUseralgid() const {return m_algid;}

    /**
    * @brief Getter of the user's salt.
    * @return User's salt.
    */
    QString getUsersalt() const {return m_salt;}

    /**
    * @brief Getter of the user's password hash.
    * @return User's password hash.
    */
    QString getUserhash() const {return m_hashofpass;}

    /**
    * @brief Get a hashing scheme's name by scheme's ID.
    * @param algid - hashing algorithm (scheme) ID.
    * @return Hashing scheme's name.
    */
    static QString getAlgorithmName(const QString& algid);

    /**
    * @brief Interrupts collisionAttackTask_CPU jobs, stops the attack's calculations.
    * collision_attack() completion command.
    * @see collisionAttackTask_CPU, collisionAttackTask_CPU::stopAttack(), collision_attack()
    */
    void attack_interrupt();

public slots:

    /**
    * @brief Performs the user's password parallel finding
    * (each "password length"<->"heuristics mode" combo calculations performs in a separate thread).
    * @see collisionAttackTask_CPU
    */
    void collision_attack();

signals:

    /**
    * @brief This signal is emitted when the calculations ending process has been activated and
    * the attack has been successfully interrupted (after attack_interrupt() has been called).
    * @see attack_interrupt()
    */
    void signal_attackFinished();

private:
    QString m_username;

    /**
    * @brief Hash scheme ID.
    */
    QString m_algid;
    QString m_salt;

    /**
    * @brief Password's hash.
    */
    QString m_hashofpass;

    /**
    * @brief Supported hashing schemes.
    * key - algorithm id, value - algorithm name.
    */
    static std::map<QString, QString> m_halgorithm_types;

};

Q_DECLARE_METATYPE(user)

#endif // USER_H
