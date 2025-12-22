// Enhanced Funny Loader with rotating messages and talking wise man
let messageRotationInterval = null;
let wiseManTimeout = null;
let currentMessageIndex = 0;

function showFunnyLoader() {
    const funnyMessages = [
        "🐛 Sending bugs to investigate your file...",
        "🦠 Unleashing virtual viruses to catch real ones...",
        "🔬 Our microscopic minions are examining every byte...",
        "🕵️ Detective Bug is on the case!",
        "🐜 Army of ants carrying your file to the lab...",
        "🦟 Mosquito squad is sucking out malicious code...",
        "🕷️ Spider-Bot is spinning a web of analysis...",
        "🐞 Ladybug is debugging... literally!",
        "🦂 Scorpion scanner stinging every suspicious bit...",
        "🪲 Beetle battalion marching through your binary...",
        "🧬 Mutating our analyzers to catch shape-shifters...",
        "🎯 Lock and load! Targeting malicious patterns...",
        "🔮 Consulting the crystal ball of cybersecurity...",
        "🎪 The malware circus is in town!",
        "🎭 Unmasking digital disguises...",
        "🍕 Feeding your file to hungry algorithms...",
        "☕ Brewing a fresh batch of analysis...",
        "🎮 Playing hide and seek with malware...",
        "🏃 Running a marathon through your code...",
        "🎨 Painting a picture of potential threats...",
        "🧲 Magnetically attracting suspicious patterns...",
        "🎪 Watch the malware acrobats perform!",
        "🔍 Sherlock Bytes is investigating...",
        "🚀 Launching analysis missiles at your file...",
        "🧪 Cooking up a security potion...",
        "🎬 Rolling out the red carpet for your malware...",
        "🔬 Putting on our lab coats and safety goggles...",
        "🎯 Bullseye! Targeting suspicious activities...",
        "🧠 Our AI brain cells are thinking hard...",
        "⚡ Zapping malicious code with lightning speed...",
        "🎪 Step right up to the malware show!",
        "🔥 Burning through layers of obfuscation...",
        "🎸 Jamming with the bytes...",
        "🍿 Grab some popcorn, this might take a moment...",
        "🎲 Rolling the dice of detection..."
    ];

    const malwareFacts = [
        "Did you know? The first computer virus was created in 1983 and was called 'Elk Cloner'. It infected Apple II computers via floppy disks!",
        "Fun fact: The ILOVEYOU virus in 2000 caused $10 billion in damages worldwide. It spread through email with a love letter subject line!",
        "Interesting: Ransomware attacks happen every 11 seconds globally. Always keep your backups secure!",
        "Did you know? The Stuxnet worm was designed to target specific industrial equipment and is considered the first cyber weapon!",
        "Malware insight: Polymorphic viruses can change their code to avoid detection. They're like shape-shifters!",
        "Security tip: Over 90% of malware is delivered through phishing emails. Always verify sender addresses!",
        "Historical fact: The Morris Worm in 1988 was one of the first worms distributed via the internet, affecting 6,000 computers!",
        "Did you know? The average cost of a data breach in 2024 exceeded $4.5 million per incident!",
        "Crypto fact: Cryptojacking malware secretly mines cryptocurrency using your computer's resources!",
        "Scary stat: A new malware sample is created every 4.2 seconds globally!",
        "Protection tip: Keeping software updated patches 85% of vulnerabilities that malware exploits!",
        "Did you know? Some malware can survive even after you reinstall your operating system by hiding in firmware!",
        "Trojan insight: Trojans are named after the legendary Trojan Horse - they disguise themselves as legitimate software!",
        "Mobile malware: Android devices face over 2 million malware attacks daily. iOS isn't immune either!",
        "AI evolution: Modern malware uses artificial intelligence to adapt and evade security systems!",
        "Banking threat: Financial malware steals over $100 billion annually from online banking users worldwide!",
        "IoT danger: Smart devices are increasingly targeted - even smart refrigerators have been hacked!",
        "Persistence technique: Some malware modifies system restore points to survive removal attempts!",
        "Zero-day exploits: These attacks target vulnerabilities unknown to software developers - very dangerous!",
        "Botnet power: The Mirai botnet infected over 600,000 IoT devices and launched massive DDoS attacks!"
    ];
    
    currentMessageIndex = Math.floor(Math.random() * funnyMessages.length);
    
    const loader = document.createElement('div');
    loader.id = 'funny-loader';
    loader.innerHTML = `
        <div class="loader-overlay">
            <div class="loader-content">
                <div class="bug-container">
                    <div class="bug">
                        <div class="bug-body">
                            <div class="bug-eye left"></div>
                            <div class="bug-eye right"></div>
                            <div class="bug-antenna left"></div>
                            <div class="bug-antenna right"></div>
                        </div>
                        <div class="bug-legs">
                            <div class="leg leg-1"></div>
                            <div class="leg leg-2"></div>
                            <div class="leg leg-3"></div>
                            <div class="leg leg-4"></div>
                            <div class="leg leg-5"></div>
                            <div class="leg leg-6"></div>
                        </div>
                    </div>
                </div>
                <div class="loader-message" id="loader-message">${funnyMessages[currentMessageIndex]}</div>
                <div class="loader-dots">
                    <span></span><span></span><span></span>
                </div>
                
                <!-- Wise Man Container -->
                <div class="wise-man-container" id="wise-man-container" style="display: none;">
                    <div class="wise-man-speech-bubble" id="wise-man-speech">
                        <p></p>
                    </div>
                    <div class="wise-man">
                        <div class="wise-man-head">
                            <div class="wise-man-eye left"></div>
                            <div class="wise-man-eye right"></div>
                            <div class="wise-man-mouth"></div>
                            <div class="wise-man-beard"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(loader);
    
    // Rotate messages every 7 seconds
    messageRotationInterval = setInterval(() => {
        currentMessageIndex = (currentMessageIndex + 1) % funnyMessages.length;
        const messageElement = document.getElementById('loader-message');
        if (messageElement) {
            messageElement.style.animation = 'none';
            setTimeout(() => {
                messageElement.textContent = funnyMessages[currentMessageIndex];
                messageElement.style.animation = 'fadeInMessage 0.5s ease';
            }, 50);
        }
    }, 10000);
    
    // Show wise man after 8 seconds with a random fact
    function showWiseMan() {
        const wiseManContainer = document.getElementById('wise-man-container');
        const speechBubble = document.getElementById('wise-man-speech');
        
        if (wiseManContainer && speechBubble) {
            const randomFact = malwareFacts[Math.floor(Math.random() * malwareFacts.length)];
            speechBubble.querySelector('p').textContent = randomFact;
            
            wiseManContainer.style.display = 'flex';
            wiseManContainer.style.animation = 'slideInWiseMan 0.5s ease forwards';
            
            // Hide after 6 seconds
            setTimeout(() => {
                wiseManContainer.style.animation = 'slideOutWiseMan 0.5s ease forwards';
                setTimeout(() => {
                    wiseManContainer.style.display = 'none';
                    
                    // Show again after 8 seconds if loader still active
                    wiseManTimeout = setTimeout(showWiseMan, 8000);
                }, 500);
            }, 6000);
        }
    }
    
    // Start wise man appearance after 8 seconds
    wiseManTimeout = setTimeout(showWiseMan, 8000);
    
    // Add styles if not already added
    if (!document.getElementById('funny-loader-styles')) {
        const style = document.createElement('style');
        style.id = 'funny-loader-styles';
        style.textContent = `
            #funny-loader .loader-overlay {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(133, 25, 213, 0.95);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 9999;
                animation: fadeIn 0.3s ease;
            }
            
            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
            
            @keyframes fadeOut {
                from { opacity: 1; }
                to { opacity: 0; }
            }
            
            #funny-loader .loader-content {
                text-align: center;
                color: white;
            }
            
            .bug-container {
                width: 150px;
                height: 150px;
                margin: 0 auto 2rem;
                position: relative;
                animation: crawl 3s linear infinite;
            }
            
            @keyframes crawl {
                0% { transform: translateX(-50vw) rotate(0deg); }
                50% { transform: translateX(50vw) rotate(180deg); }
                100% { transform: translateX(-50vw) rotate(360deg); }
            }
            
            .bug {
                position: relative;
                animation: wiggle 0.3s ease-in-out infinite;
            }
            
            @keyframes wiggle {
                0%, 100% { transform: rotate(-5deg); }
                50% { transform: rotate(5deg); }
            }
            
            .bug-body {
                width: 80px;
                height: 100px;
                background: linear-gradient(145deg, #ff6b6b, #ee5a6f);
                border-radius: 50% 50% 50% 50% / 60% 60% 40% 40%;
                position: relative;
                margin: 0 auto;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            }
            
            .bug-eye {
                width: 20px;
                height: 20px;
                background: white;
                border-radius: 50%;
                position: absolute;
                top: 20px;
                box-shadow: inset 0 2px 5px rgba(0, 0, 0, 0.2);
            }
            
            .bug-eye::after {
                content: '';
                width: 10px;
                height: 10px;
                background: #333;
                border-radius: 50%;
                position: absolute;
                top: 5px;
                left: 5px;
                animation: lookAround 2s ease-in-out infinite;
            }
            
            @keyframes lookAround {
                0%, 100% { transform: translate(0, 0); }
                25% { transform: translate(-3px, 0); }
                75% { transform: translate(3px, 0); }
            }
            
            .bug-eye.left { left: 15px; }
            .bug-eye.right { right: 15px; }
            
            .bug-antenna {
                width: 3px;
                height: 35px;
                background: #ff8787;
                position: absolute;
                top: -25px;
                border-radius: 3px;
                transform-origin: bottom;
                animation: antennaWave 1s ease-in-out infinite;
            }
            
            .bug-antenna::after {
                content: '';
                width: 10px;
                height: 10px;
                background: #ffadad;
                border-radius: 50%;
                position: absolute;
                top: -8px;
                left: -3.5px;
            }
            
            .bug-antenna.left {
                left: 20px;
                transform: rotate(-20deg);
            }
            
            .bug-antenna.right {
                right: 20px;
                transform: rotate(20deg);
                animation-delay: 0.5s;
            }
            
            @keyframes antennaWave {
                0%, 100% { transform: rotate(-20deg); }
                50% { transform: rotate(-40deg); }
            }
            
            .bug-legs {
                position: absolute;
                width: 100%;
                height: 100%;
                top: 0;
                left: 0;
            }
            
            .leg {
                width: 4px;
                height: 40px;
                background: #ff8787;
                position: absolute;
                border-radius: 4px;
                transform-origin: top;
            }
            
            .leg-1, .leg-2, .leg-3 {
                left: -5px;
                animation: legWalk 0.6s ease-in-out infinite;
            }
            
            .leg-4, .leg-5, .leg-6 {
                right: -5px;
                animation: legWalk 0.6s ease-in-out infinite;
            }
            
            .leg-1 { top: 30px; }
            .leg-2 { top: 50px; animation-delay: 0.2s; }
            .leg-3 { top: 70px; animation-delay: 0.4s; }
            .leg-4 { top: 30px; animation-delay: 0.1s; }
            .leg-5 { top: 50px; animation-delay: 0.3s; }
            .leg-6 { top: 70px; animation-delay: 0.5s; }
            
            @keyframes legWalk {
                0%, 100% { transform: rotate(20deg); }
                50% { transform: rotate(-20deg); }
            }
            
            .loader-message {
                font-size: 1.5rem;
                font-weight: 600;
                margin-bottom: 1rem;
                text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
                max-width: 600px;
                margin: 0 auto 1rem;
                padding: 0 1rem;
            }
            
            .loader-dots {
                display: flex;
                justify-content: center;
                gap: 0.5rem;
            }
            
            .loader-dots span {
                width: 12px;
                height: 12px;
                background: white;
                border-radius: 50%;
                animation: bounce 1.4s ease-in-out infinite;
            }
            
            .loader-dots span:nth-child(2) {
                animation-delay: 0.2s;
            }
            
            .loader-dots span:nth-child(3) {
                animation-delay: 0.4s;
            }
            
            @keyframes bounce {
                0%, 80%, 100% { transform: scale(0); }
                40% { transform: scale(1); }
            }
            
            @keyframes fadeInMessage {
                from { opacity: 0; transform: translateY(10px); }
                to { opacity: 1; transform: translateY(0); }
            }
            
            /* Wise Man Styles */
            .wise-man-container {
                position: fixed;
                bottom: -400px;
                right: 50px;
                display: flex;
                flex-direction: column;
                align-items: center;
                z-index: 10000;
            }
            
            @keyframes slideInWiseMan {
                from { bottom: -400px; opacity: 0; }
                to { bottom: 30px; opacity: 1; }
            }
            
            @keyframes slideOutWiseMan {
                from { bottom: 30px; opacity: 1; }
                to { bottom: -400px; opacity: 0; }
            }
            
            .wise-man {
                position: relative;
                width: 140px;
                height: 140px;
                animation: floatWiseMan 3s ease-in-out infinite;
                filter: drop-shadow(0 15px 35px rgba(0,0,0,0.4));
            }
            
            @keyframes floatWiseMan {
                0%, 100% { transform: translateY(0px) rotate(-2deg); }
                50% { transform: translateY(-15px) rotate(2deg); }
            }
            
            .wise-man-head {
                width: 100px;
                height: 100px;
                background: linear-gradient(145deg, #ffeaa7, #fdcb6e);
                border-radius: 50%;
                position: relative;
                margin: 0 auto;
                box-shadow: inset 0 -10px 20px rgba(0,0,0,0.1),
                            0 10px 30px rgba(253, 203, 110, 0.6);
                border: 3px solid #fff;
            }
            
            .wise-man-hat {
                position: absolute;
                top: -50px;
                left: 50%;
                transform: translateX(-50%);
                font-size: 70px;
                filter: drop-shadow(0 8px 15px rgba(0,0,0,0.4));
                animation: wobbleHat 4s ease-in-out infinite;
            }
            
            @keyframes wobbleHat {
                0%, 100% { transform: translateX(-50%) rotate(-5deg); }
                50% { transform: translateX(-50%) rotate(5deg); }
            }
            
            .wise-man-beard {
                width: 75px;
                height: 50px;
                background: linear-gradient(180deg, #fff 0%, #f0f0f0 100%);
                border-radius: 0 0 40px 40px / 0 0 50px 50px;
                position: absolute;
                bottom: -25px;
                left: 50%;
                transform: translateX(-50%);
                box-shadow: 0 8px 20px rgba(0,0,0,0.2),
                            inset 0 -5px 10px rgba(0,0,0,0.05);
                border: 2px solid #fff;
            }
            
            .wise-man-beard::before {
                content: '';
                position: absolute;
                width: 20px;
                height: 20px;
                background: linear-gradient(135deg, #fff 0%, #f0f0f0 100%);
                border-radius: 50%;
                left: -8px;
                bottom: 15px;
                box-shadow: 0 3px 8px rgba(0,0,0,0.15);
            }
            
            .wise-man-beard::after {
                content: '';
                position: absolute;
                width: 20px;
                height: 20px;
                background: linear-gradient(135deg, #fff 0%, #f0f0f0 100%);
                border-radius: 50%;
                right: -8px;
                bottom: 15px;
                box-shadow: 0 3px 8px rgba(0,0,0,0.15);
            }
            
            .wise-man-eye {
                width: 12px;
                height: 12px;
                background: #2d3436;
                border-radius: 50%;
                position: absolute;
                top: 35px;
                animation: blinkWiseMan 4s infinite;
                box-shadow: inset 0 2px 4px rgba(0,0,0,0.3);
            }
            
            .wise-man-eye.left {
                left: 25px;
            }
            
            .wise-man-eye.right {
                right: 25px;
            }
            
            .wise-man-eye::after {
                content: '';
                position: absolute;
                width: 4px;
                height: 4px;
                background: white;
                border-radius: 50%;
                top: 2px;
                left: 2px;
            }
            
            @keyframes blinkWiseMan {
                0%, 48%, 52%, 100% { height: 12px; }
                50% { height: 2px; }
            }
            
            .wise-man-mouth {
                width: 25px;
                height: 15px;
                border: 3px solid #e17055;
                border-top: none;
                border-radius: 0 0 25px 25px;
                position: absolute;
                bottom: 30px;
                left: 50%;
                transform: translateX(-50%);
                animation: talkMouth 0.4s ease-in-out infinite;
                background: linear-gradient(180deg, transparent 0%, rgba(225, 112, 85, 0.1) 100%);
            }
            
            @keyframes talkMouth {
                0%, 100% { 
                    height: 15px;
                    transform: translateX(-50%) scaleY(1);
                    border-radius: 0 0 25px 25px;
                }
                50% { 
                    height: 8px;
                    transform: translateX(-50%) scaleY(0.5);
                    border-radius: 0 0 15px 15px;
                }
            }
            
            .wise-man-speech-bubble {
                background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
                color: #2d3436;
                padding: 25px 30px;
                border-radius: 20px;
                max-width: 400px;
                margin-bottom: 25px;
                position: relative;
                box-shadow: 0 15px 45px rgba(0,0,0,0.3),
                            0 5px 15px rgba(133, 25, 213, 0.2);
                animation: pulseSpeech 2s ease-in-out infinite;
                border: 3px solid rgba(133, 25, 213, 0.3);
            }
            
            @keyframes pulseSpeech {
                0%, 100% { 
                    transform: scale(1);
                    box-shadow: 0 15px 45px rgba(0,0,0,0.3),
                                0 5px 15px rgba(133, 25, 213, 0.2);
                }
                50% { 
                    transform: scale(1.03);
                    box-shadow: 0 20px 50px rgba(0,0,0,0.35),
                                0 8px 20px rgba(133, 25, 213, 0.3);
                }
            }
            
            .wise-man-speech-bubble::before {
                content: '💡';
                position: absolute;
                top: -15px;
                left: 20px;
                font-size: 30px;
                animation: rotateBulb 4s ease-in-out infinite;
            }
            
            @keyframes rotateBulb {
                0%, 100% { transform: rotate(-10deg); }
                50% { transform: rotate(10deg); }
            }
            
            .wise-man-speech-bubble::after {
                content: '';
                position: absolute;
                bottom: -20px;
                right: 50px;
                width: 0;
                height: 0;
                border-left: 20px solid transparent;
                border-right: 20px solid transparent;
                border-top: 25px solid #ffffff;
                filter: drop-shadow(0 5px 10px rgba(0,0,0,0.2));
            }
            
            .wise-man-speech-bubble p {
                margin: 0;
                font-size: 16px;
                line-height: 1.8;
                font-weight: 600;
                color: #2d3436;
                text-shadow: none;
            }
        `;
        document.head.appendChild(style);
    }
}

function hideFunnyLoader() {
    // Clear intervals and timeouts
    if (messageRotationInterval) {
        clearInterval(messageRotationInterval);
        messageRotationInterval = null;
    }
    if (wiseManTimeout) {
        clearTimeout(wiseManTimeout);
        wiseManTimeout = null;
    }
    
    const loader = document.getElementById('funny-loader');
    if (loader) {
        loader.querySelector('.loader-overlay').style.animation = 'fadeOut 0.3s ease';
        setTimeout(() => loader.remove(), 300);
    }
}
