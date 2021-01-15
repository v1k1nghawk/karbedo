#ifndef USER_H
#define USER_H

#include "collisionAttackTask_CPU.h"


/**
 * @class user
 * @brief Description of attack's target.
 */
class user : public QObject
{
    Q_OBJECT

public:
    user(const QString& username="", const QString& algid="", const QString& salt="", const QString& hashofpass="", QObject *parent=Q_NULLPTR);

    /**
    * @brief Constructs user object from JSON. Throws ParsingException if JSON object is incomplete w.r.t. user class.
    */
    user(const QJsonObject& json, QObject *parent=Q_NULLPTR);

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
    QString getName() const {return m_username;}

    /**
    * @brief Gets user's hashing algorithm (scheme) ID.
    * @return User's hashing algorithm (scheme) ID.
    */
    QString getAlgid() const {return m_algid;}

    /**
    * @brief Getter of the user's salt.
    * @return User's salt.
    */
    QString getSalt() const {return m_salt;}

    /**
    * @brief Getter of the user's password hash.
    * @return User's password hash.
    */
    QString getHash() const {return m_hashofpass;}

    /**
    * @brief Get a hashing scheme's name by scheme's ID.
    * @param algid - hashing algorithm (scheme) ID.
    * @return Hashing scheme's name.
    */
    static QString getAlgorithmName(const QString& algid);

    /**
    * @brief Export values from the User object to json.
    * @param json - JSON object.
    */
    void write_to_json(QJsonObject& json) const;

    /**
    * @brief Interrupts collisionAttackTask_CPU jobs, stops the attack's calculations.
    * collision_attack()/resumed_collision_attack() completion command.
    * @see collisionAttackTask_CPU, collisionAttackTask_CPU::stopAttack(), collision_attack(), attack_save()
    */
    void attack_interrupt();

    /**
    * @brief Saves the user's attack's calculations, interrupts collisionAttackTask_CPU jobs,
    * stops the attack's calculations.
    * collision_attack()/resumed_collision_attack() completion command.
    * @see collisionAttackTask_CPU::saveAttack(), collision_attack(), resumed_collision_attack(), attack_interrupt()
    */
    void attack_save();

public slots:

    /**
    * @brief Performs the user's password's parallel finding.
    * (each "password length"<->"heuristics mode" combo calculations performs in a separate thread).
    * @see collisionAttackTask_CPU
    */
    void collision_attack();

    /**
    * @brief Continues the user's password's parallel finding.
    * (each "password length"<->"heuristics mode" combo calculations performs in a separate thread,
    * starts from cached passwords as already reached milestone).
    * @see collisionAttackTask_CPU
    */
    void resumed_collision_attack();

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

    /**
    * @brief Hash function input modifier.
    */
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

    /**
    * @brief Performs restricted brute-force attack with limited maximum password length and restricted alphabet.
    * Runs (collisionAttackTask_CPU::m_optimal_max_pass_length - \a initial_password_length) separate attacks
    * with different password's length.
    * @param initial_password_length - minimum size (quantity of characters) of password for the attack's tasks.
    * @see collisionAttackTask_CPU::Heuristic, unlimited_attack()
    */
    void limited_attack(const uint& initial_password_length);

    /**
    * @brief Performs unrestricted brute-force attack without any Heuristics.
    * Runs unlimited quantity of attacks until interruption.
    * @param initial_password_length - minimum size (quantity of characters) of password for the attack's tasks.
    * @see collisionAttackTask_CPU::Heuristic, limited_attack(), attack_interrupt(), attack_save()
    */
    void unlimited_attack(const uint& initial_password_length);
};

Q_DECLARE_METATYPE(user)

#endif // USER_H
